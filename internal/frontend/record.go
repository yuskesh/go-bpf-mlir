package frontend

import (
	"fmt"
	"go/token"
	"go/types"
	"reflect"
	"sort"
	"strings"
)

// record — a Go struct declaration → SharedABI.
//
// Rules:
//   - a record is a named struct type of the same package. Fields are fixed-width integers (8 to 64 bit), fixed-length arrays of fixed-width integers, and explicit padding `_ [N]byte`
//   - every named field is exported and has a `schema:"…"` tag (go/layout's Check needs it)
//   - **implicit padding is refused** — finds holes between fields and at the end by go/types' amd64 offsets and shows the `_ [N]byte` needed
//   - nested records, bool, pointer, slice, string, map, interface, float and int / uint (arch-dependent width) are refused (GB016)
// The layout is go/types' Sizes (amd64 — the target is Linux x86_64 only; integer and array sizes and alignment are the same as the BPF target).

var amd64Sizes = types.SizesFor("gc", "amd64")

// recordOf turns t (a bpf type argument) into a record SharedABI. Errors are reported as GB016 and it returns false. what is the report context (for example "map Counts value").
func (a *analyzer) recordOf(t types.Type, at token.Pos, what string) (SharedABI, bool) {
	named, ok := t.(*types.Named)
	var st *types.Struct
	if ok {
		st, _ = named.Underlying().(*types.Struct)
	}
	if st == nil {
		a.report(Rejected, GB009MapDeclShape, at, nil, "%s: %s is neither a fixed-width integer nor a record (a named struct type declared in this package)", what, a.typeString(t))
		return SharedABI{}, false
	}
	if named.Obj().Pkg() != a.pkg.Types {
		a.report(Rejected, GB016SharedABIShape, at, nil, "%s: record %s must be declared in this package (the generated Decode is attached to it)", what, named.Obj().Name())
		return SharedABI{}, false
	}
	if named.TypeArgs() != nil && named.TypeArgs().Len() > 0 {
		a.report(Rejected, GB016SharedABIShape, at, nil, "%s: generic record %s is not supported", what, a.typeString(named))
		return SharedABI{}, false
	}
	if r, done := a.recordBySymbol[named.Obj().Name()]; done {
		return r, r.Kind == ABIRecord
	}
	sym := named.Obj().Name()
	fields := make([]*types.Var, st.NumFields())
	for i := range fields {
		fields[i] = st.Field(i)
	}
	offsets := amd64Sizes.Offsetsof(fields)
	size := uint64(amd64Sizes.Sizeof(st))
	align := uint64(amd64Sizes.Alignof(st))
	rec := &RecordABI{Symbol: sym, Pos: a.position(named.Obj().Pos())}
	good := true
	bad := func(p token.Pos, format string, args ...any) {
		a.report(Rejected, GB016SharedABIShape, p, []string{sym}, format, args...)
		good = false
	}
	names := map[string]bool{}
	var end uint64
	for i, f := range fields {
		off := uint64(offsets[i])
		fsize := uint64(amd64Sizes.Sizeof(f.Type()))
		if off > end {
			bad(f.Pos(), "record %s has %d bytes of implicit padding before field %s (offset %d) — declare it explicitly as `_ [%d]byte` (implicit padding is not allowed: the Go and BPF sides must agree byte for byte)", sym, off-end, f.Name(), off, off-end)
		}
		end = off + fsize
		if f.Name() == "_" {
			if !isBytePadding(f.Type()) {
				bad(f.Pos(), "record %s: a blank field must be explicit padding of type [N]byte, got %s", sym, a.typeString(f.Type()))
			}
			continue
		}
		if !f.Exported() {
			bad(f.Pos(), "record %s: field %s must be exported (the user-space side reads it)", sym, f.Name())
			continue
		}
		tag, hasTag := reflect.StructTag(st.Tag(i)).Lookup("schema")
		if !hasTag || tag == "" {
			bad(f.Pos(), "record %s: field %s needs a `schema:\"…\"` tag (the schema field name — go/layout checks it)", sym, f.Name())
			continue
		}
		if names[tag] {
			bad(f.Pos(), "record %s: schema name %q is used twice", sym, tag)
			continue
		}
		names[tag] = true
		if kind, sz, al, isSpecial := specialFieldOf(f.Type()); isSpecial {
			// bpf.SpinLock / bpf.Timer — at most one per record (bpf-mlir's schema also refuses a lock and a timer together).
			if rec.Special != nil {
				bad(f.Pos(), "record %s has more than one bpf.SpinLock / bpf.Timer field (%s and %s) — a map value holds at most one lock or one timer, not both", sym, rec.Special.GoName, f.Name())
				continue
			}
			fa := FieldABI{Name: tag, GoName: f.Name(), Offset: off, Type: SharedABI{Kind: kind, GoType: f.Type(), Size: sz, Align: al}}
			rec.Fields = append(rec.Fields, fa)
			sp := fa
			rec.Special = &sp
			continue
		}
		if hasStruct(f.Type()) {
			// a nested record (a named struct, or a 1-dimensional array of it).
			ft, depth, ok := a.nestedFieldABI(sym, f)
			if !ok {
				good = false
				continue
			}
			rec.Depth = max(rec.Depth, depth+1)
			rec.Fields = append(rec.Fields, FieldABI{Name: tag, GoName: f.Name(), Offset: off, Type: ft})
			continue
		}
		ft, ok := a.fieldABI(f.Type())
		if !ok {
			if d := arrayDims(f.Type()); d > maxArrayDims {
				bad(f.Pos(), "record %s: field %s has %d array dimensions — at most %d (bpf-mlir's record path limit)", sym, f.Name(), d, maxArrayDims)
				continue
			}
			bad(f.Pos(), "record %s: field %s has type %s — record fields are fixed-width integers, fixed-size arrays of them (up to 2 dimensions), named records declared in this package, or 1-dimensional arrays of such records (no bool, pointer, slice, string, map, interface, float, int / uint)", sym, f.Name(), a.typeString(f.Type()))
			continue
		}
		rec.Fields = append(rec.Fields, FieldABI{Name: tag, GoName: f.Name(), Offset: off, Type: ft})
	}
	rec.Depth = max(rec.Depth, 1)
	if rec.Depth > maxRecordDepth && good {
		bad(named.Obj().Pos(), "record %s nests records %d deep — at most %d (a field path has at most %d components: x.y.z — bpf-mlir's record path limit)", sym, rec.Depth, maxRecordDepth, maxRecordDepth)
	}
	if end < size && good {
		bad(named.Obj().Pos(), "record %s has %d bytes of implicit trailing padding — declare it explicitly as `_ [%d]byte` at the end", sym, size-end, size-end)
	}
	if len(rec.Fields) == 0 && good {
		bad(named.Obj().Pos(), "record %s has no named fields", sym)
	}
	if rec.Special != nil && good {
		rec.DecodeType = a.decodeTypeOf(st)
	}
	abi := SharedABI{Kind: ABIRecord, GoType: named, Size: size, Align: align, Record: rec}
	if !good {
		abi = SharedABI{} // Kind 0 — later queries do not repeat the error
	}
	a.recordBySymbol[sym] = abi
	if good {
		a.records = append(a.records, &abi)
	}
	return abi, good
}

// fieldABI returns the type of a record field (a fixed-width integer or a fixed-length array of it — up to 2 dimensions).
func (a *analyzer) fieldABI(t types.Type) (SharedABI, bool) {
	if it, ok := intTypeOf(t); ok {
		return sharedABIOfInt(t, it), true
	}
	if arr, ok := t.Underlying().(*types.Array); ok {
		if arr.Len() <= 0 {
			return SharedABI{}, false
		}
		var elem SharedABI
		if it, isInt := intTypeOf(arr.Elem()); isInt {
			elem = sharedABIOfInt(arr.Elem(), it)
		} else if inner, isArr := arr.Elem().Underlying().(*types.Array); isArr && arrayDims(t) == 2 {
			it, isInt := intTypeOf(inner.Elem())
			if !isInt || inner.Len() <= 0 {
				return SharedABI{}, false
			}
			ie := sharedABIOfInt(inner.Elem(), it)
			elem = SharedABI{Kind: ABIArray, GoType: arr.Elem(), Size: uint64(inner.Len()) * ie.Size, Align: ie.Align, Array: &ArrayABI{Count: uint64(inner.Len()), Elem: ie}}
		} else {
			return SharedABI{}, false
		}
		return SharedABI{Kind: ABIArray, GoType: t, Size: uint64(arr.Len()) * elem.Size, Align: elem.Align, Array: &ArrayABI{Count: uint64(arr.Len()), Elem: elem}}, true
	}
	return SharedABI{}, false
}

// The limits of bpf-mlir's record paths (kMaxRecordDepth / kMaxArrayDims in RecordPath.h). The frontend stops first at the Go position.
const (
	maxRecordDepth = 3
	maxArrayDims   = 2
)

// arrayDims returns the number of array dimensions of t (0 if not an array).
func arrayDims(t types.Type) int {
	n := 0
	for {
		arr, ok := t.Underlying().(*types.Array)
		if !ok {
			return n
		}
		n++
		t = arr.Elem()
	}
}

// hasStruct reports whether t is a struct or an array whose innermost element is a struct (a nested record field).
func hasStruct(t types.Type) bool {
	for {
		arr, ok := t.Underlying().(*types.Array)
		if !ok {
			break
		}
		t = arr.Elem()
	}
	_, ok := t.Underlying().(*types.Struct)
	return ok
}

// nestedFieldABI turns field f (a struct or an array of structs) of record sym into a nested record: the inner struct is a named record of the same package
// (with its own schema entry via recordOf), arrays have one dimension only (bpf-mlir limits record arrays to one dimension), and the inner record cannot hold a lock / timer
// (bpf-mlir's schema — a record with a lock / timer cannot be inside another record). The returned depth is that of the inner record. Errors are already reported.
func (a *analyzer) nestedFieldABI(sym string, f *types.Var) (SharedABI, int, bool) {
	t := f.Type()
	dims := arrayDims(t)
	if dims > 1 {
		a.report(Rejected, GB016SharedABIShape, f.Pos(), []string{sym}, "record %s: field %s is a %d-dimensional array of records — an array of records has one dimension (bpf-mlir's record path limit)", sym, f.Name(), dims)
		return SharedABI{}, 0, false
	}
	elemT := t
	if dims == 1 {
		elemT = t.Underlying().(*types.Array).Elem()
	}
	named, isNamed := elemT.(*types.Named)
	if !isNamed || isBPFNamed(elemT, "SpinLock") || isBPFNamed(elemT, "Timer") {
		what := "an anonymous struct"
		if isNamed {
			what = a.typeString(elemT)
		}
		a.report(Rejected, GB016SharedABIShape, f.Pos(), []string{sym}, "record %s: field %s holds %s — a nested record is a named struct type declared in this package (its name is the schema record)", sym, f.Name(), what)
		return SharedABI{}, 0, false
	}
	inner, ok := a.recordOf(named, f.Pos(), fmt.Sprintf("record %s field %s", sym, f.Name()))
	if !ok {
		return SharedABI{}, 0, false // the inner record's error is already reported
	}
	if sp := inner.Record.Special; sp != nil {
		a.report(Rejected, GB016SharedABIShape, f.Pos(), []string{sym}, "record %s: field %s is the record %s, which holds %s %s — a record with a lock or timer cannot be nested in another record (bpf-mlir's schema); put the lock / timer in %s itself", sym, f.Name(), inner.Record.Symbol, specialName(sp.Type.Kind), sp.GoName, sym)
		return SharedABI{}, 0, false
	}
	if dims == 0 {
		return inner, inner.Record.Depth, true
	}
	arr := t.Underlying().(*types.Array)
	if arr.Len() <= 0 {
		a.report(Rejected, GB016SharedABIShape, f.Pos(), []string{sym}, "record %s: field %s is an empty array", sym, f.Name())
		return SharedABI{}, 0, false
	}
	return SharedABI{Kind: ABIArray, GoType: t, Size: uint64(arr.Len()) * inner.Size, Align: inner.Align, Array: &ArrayABI{Count: uint64(arr.Len()), Elem: inner}}, inner.Record.Depth, true
}

func isBytePadding(t types.Type) bool {
	arr, ok := t.Underlying().(*types.Array)
	if !ok {
		return false
	}
	b, ok := arr.Elem().Underlying().(*types.Basic)
	return ok && b.Kind() == types.Uint8
}

// leafPaths returns the leaf paths of a record (record.make needs all of them — "x" for an integer, "x[0]" … "x[n-1]" for an array) and their types in declaration order.
func (r *RecordABI) leafPaths() []leaf {
	var out []leaf
	for _, f := range r.Fields {
		switch f.Type.Kind {
		case ABIInt:
			out = append(out, leaf{path: f.Name, field: f, index: -1, t: *f.Type.Int})
		case ABIArray:
			for i := uint64(0); i < f.Type.Array.Count; i++ {
				out = append(out, leaf{path: indexPath(f.Name, i), field: f, index: int64(i), t: *f.Type.Array.Elem.Int})
			}
		}
	}
	return out
}

type leaf struct {
	path  string
	field FieldABI
	index int64 // -1 for an integer field
	t     IntType
}

func indexPath(name string, i uint64) string { return name + "[" + uitoa(i) + "]" }

func uitoa(v uint64) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

// fieldByGoName looks up a FieldABI by its Go field name.
func (r *RecordABI) fieldByGoName(name string) (FieldABI, bool) {
	for _, f := range r.Fields {
		if f.GoName == name {
			return f, true
		}
	}
	return FieldABI{}, false
}

// sortedRecords returns records in symbol order (a deterministic order for the schema and the generated file).
func sortedRecords(rs []*SharedABI) []*SharedABI {
	out := append([]*SharedABI(nil), rs...)
	sort.Slice(out, func(i, j int) bool { return out[i].Record.Symbol < out[j].Record.Symbol })
	return out
}

// DecodeLines returns the body statements of Decode of the generated gobpf_T (reads by offset — exactly the schema declaration, independent of Go's struct packing).
func (r *RecordABI) DecodeLines() []string {
	var out []string
	for _, f := range r.Fields {
		switch {
		case f.Type.Kind == ABIInt:
			out = append(out, fmt.Sprintf("gobpf.DecodeLE(&v.%s, b[%d:])", f.GoName, f.Offset))
		case f.Type.Kind == ABIArray && f.Type.Array.Elem.Kind == ABIInt:
			out = append(out, fmt.Sprintf("for i := range v.%s {\n\t\tgobpf.DecodeLE(&v.%s[i], b[%d+%d*i:])\n\t}", f.GoName, f.GoName, f.Offset, f.Type.Array.Elem.Size))
		case f.Type.Kind == ABISpinLock || f.Type.Kind == ABITimer:
			// an untouched hole (Decode does not read it)
		default:
			// nested records, record arrays, 2-dimensional arrays — recurse to the leaves (offset is an expression, the array index variables are i0, i1, … per depth).
			out = append(out, decodeNested("v."+f.GoName, fmt.Sprint(f.Offset), f.Type, 0, "\t")...)
		}
	}
	return out
}

// decodeNested returns the Decode statements of a nested field. goExpr is the Go side expression, off the expression for the byte offset from the start of the record.
func decodeNested(goExpr, off string, t SharedABI, depth int, indent string) []string {
	switch t.Kind {
	case ABIInt:
		return []string{fmt.Sprintf("gobpf.DecodeLE(&%s, b[%s:])", goExpr, off)}
	case ABIRecord:
		var out []string
		for _, f := range t.Record.Fields {
			out = append(out, decodeNested(goExpr+"."+f.GoName, fmt.Sprintf("%s+%d", off, f.Offset), f.Type, depth, indent)...)
		}
		return out
	case ABIArray:
		i := fmt.Sprintf("i%d", depth)
		body := decodeNested(goExpr+"["+i+"]", fmt.Sprintf("%s+%d*%s", off, t.Array.Elem.Size, i), t.Array.Elem, depth+1, indent+"\t")
		s := fmt.Sprintf("for %s := range %s {\n", i, goExpr)
		for _, l := range body {
			s += indent + "\t" + strings.ReplaceAll(l, "\n", "\n\t") + "\n"
		}
		return []string{s + indent + "}"}
	}
	return []string{fmt.Sprintf("panic(%q)", "gobpf: unsupported record member "+goExpr)}
}

// IsRecord reports whether the SharedABI is a record (for the generator template).
func (s SharedABI) IsRecord() bool { return s.Kind == ABIRecord }

// typeString writes a type by its name from inside the package (for diagnostics — no import path on types of the same package).
func (a *analyzer) typeString(t types.Type) string {
	return types.TypeString(t, types.RelativeTo(a.pkg.Types))
}

// specialFieldOf returns the ABI kind, size and alignment if t is bpf.SpinLock / bpf.Timer (the UAPI's struct bpf_spin_lock / bpf_timer).
func specialFieldOf(t types.Type) (ABIKind, uint64, uint64, bool) {
	switch {
	case isBPFNamed(t, "SpinLock"):
		return ABISpinLock, 4, 4, true
	case isBPFNamed(t, "Timer"):
		return ABITimer, 16, 8, true
	}
	return 0, 0, 0, false
}

// decodeTypeOf returns the generated gobpf_T type of a record with a lock / timer: a struct with the same fields in the same order and offsets, with the lock / timer as
// an opaque blank hole of bpf-mlir's go/layout (`_ [N]byte` + tag `schema:"<name>" opaque:"bpf_spin_lock|bpf_timer"`). The user's type has a field name, but
// the generated Decode type makes it an untouched hole (layout.CheckDecode checks it against the special BTF member).
func (a *analyzer) decodeTypeOf(st *types.Struct) string {
	var b strings.Builder
	b.WriteString("struct {\n")
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		tag := reflect.StructTag(st.Tag(i)).Get("schema")
		switch kind, sz, _, special := specialFieldOf(f.Type()); {
		case special:
			on := "bpf_spin_lock"
			if kind == ABITimer {
				on = "bpf_timer"
			}
			fmt.Fprintf(&b, "\t_ [%d]byte `schema:%q opaque:%q`\n", sz, tag, on)
		case f.Name() == "_":
			fmt.Fprintf(&b, "\t_ %s\n", a.typeString(f.Type()))
		default:
			fmt.Fprintf(&b, "\t%s %s `schema:%q`\n", f.Name(), a.typeString(f.Type()), tag)
		}
	}
	b.WriteString("}")
	return b.String()
}

// specialName returns the Go name of a lock / timer field type (for diagnostics).
func specialName(k ABIKind) string {
	if k == ABITimer {
		return "a bpf.Timer"
	}
	return "a bpf.SpinLock"
}
