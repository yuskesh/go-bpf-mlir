//go:build linux

package kload

// Live queries for tracefs event fields and vmlinux struct_ops members.
// Replacement BTF is caller-supplied, not owned by LiveCaps; ebpf-precheck
// --ext-target uses CheckExtTargetBTF for it.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/btfexact"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// TPFormatField describes a tracefs field's offset, size and sign.
type TPFormatField struct {
	Name         string
	Offset, Size int
	Signed       bool
	Declaration  string // retain type evidence, not just the same-sized integer view.
}

var tpFieldName = regexp.MustCompile(`([A-Za-z_][A-Za-z0-9_]*)\s*\)?\s*(?:\[[^]]*\]\s*)*$`)

// tpByteArrayShape returns a fixed byte array's count and explicit signedness.
// A known non-array/non-byte declaration has count zero; opaque types stay Unknown.
func tpByteArrayShape(f TPFormatField) (count int, sign string, known bool) {
	d := strings.TrimSpace(f.Declaration)
	if d == "" {
		return 0, "", false
	}
	if strings.ContainsAny(d, "*()") || strings.Contains(d, "__data_loc") || strings.Contains(d, "__rel_loc") || strings.Count(d, "[") > 1 {
		return 0, "", true
	}
	loc := tpFieldName.FindStringSubmatchIndex(d)
	if loc == nil {
		return 0, "", false
	}
	var base []string
	for _, tok := range strings.Fields(d[:loc[2]]) {
		if tok != "const" && tok != "volatile" {
			base = append(base, tok)
		}
	}
	switch strings.Join(base, " ") {
	case "__u8", "u8", "unsigned char":
		sign = "u"
	case "__s8", "s8", "signed char":
		sign = "i"
	case "char": // target's numeric Signed is authoritative for plain char.
	case "short", "unsigned short", "signed short", "int", "unsigned int", "signed int", "long", "unsigned long", "signed long", "long long", "unsigned long long", "__u16", "u16", "__s16", "s16", "__u32", "u32", "__s32", "s32", "__u64", "u64", "__s64", "s64", "bool":
		return 0, "", true
	default:
		return 0, "", false
	}
	tail := strings.TrimSpace(d[loc[3]:])
	if tail == "" {
		return 0, "", true
	}
	if !strings.HasPrefix(tail, "[") || !strings.HasSuffix(tail, "]") {
		return 0, "", false
	}
	n, err := strconv.Atoi(strings.TrimSpace(tail[1 : len(tail)-1]))
	if err != nil || n <= 0 {
		return 0, "", false
	}
	return n, sign, true
}

// tpCharPointerDepth distinguishes a char pointer from arrays, integers and opaque aliases.
func tpCharPointerDepth(f TPFormatField) (depth int, known bool) {
	decl := strings.TrimSpace(f.Declaration)
	if decl == "" {
		return 0, false
	}
	if strings.ContainsAny(decl, "[]") || strings.Contains(decl, "__data_loc") || strings.Contains(decl, "__rel_loc") {
		return 0, true
	}
	loc := tpFieldName.FindStringSubmatchIndex(decl)
	if loc == nil {
		return 0, false
	}
	tokens := strings.Fields(strings.ReplaceAll(decl[:loc[2]], "*", " * "))
	var base []string
	for _, token := range tokens {
		switch token {
		case "const", "volatile", "restrict":
		case "*":
			depth++
		default:
			base = append(base, token)
		}
	}
	if len(base) == 1 && base[0] == "char" {
		return depth, true
	}
	for _, token := range base {
		switch token {
		case "void", "int", "long", "short", "signed", "unsigned", "char", "bool":
		default:
			return 0, false
		}
	}
	return 0, len(base) > 0
}

// ParseTracepointFormat reads field:<declaration>; offset:N; size:N; signed:N
// lines, including common_* headers. Take the final identifier after array
// suffix removal; __data_loc char[] name still names the field name.
func ParseTracepointFormat(text string) ([]TPFormatField, error) {
	var out []TPFormatField
	for _, l := range strings.Split(text, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "field:") {
			continue
		}
		var decl string
		var f TPFormatField
		var got int
		for _, part := range strings.Split(l, ";") {
			part = strings.TrimSpace(part)
			k, v, ok := strings.Cut(part, ":")
			if !ok {
				continue
			}
			switch k {
			case "field":
				decl = v
			case "offset", "size", "signed":
				n, err := strconv.Atoi(v)
				if err != nil {
					return nil, fmt.Errorf("tracepoint format: bad %s in %q", k, l)
				}
				switch k {
				case "offset":
					f.Offset = n
				case "size":
					f.Size = n
				case "signed":
					f.Signed = n != 0
				}
				got++
			}
		}
		f.Declaration = strings.TrimSpace(decl)
		name := tpFieldName.FindStringSubmatch(decl)
		if len(name) == 0 || got != 3 {
			return nil, fmt.Errorf("tracepoint format: cannot read %q", l)
		}
		f.Name = name[1]
		out = append(out, f)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("tracepoint format: no field lines")
	}
	return out, nil
}

// CompareTracepointField returns mismatches between format fields and tpfield,
// or empty on agreement.
func CompareTracepointField(event string, fields []TPFormatField, field string, offset, bytes int, sign string) []string {
	for _, f := range fields {
		if f.Name != field {
			continue
		}
		if strings.HasPrefix(sign, "[") {
			n, explicit, known := tpByteArrayShape(f)
			wantSign := "u"
			if strings.HasSuffix(sign, "]i8") {
				wantSign = "i"
			}
			gotSign := "u"
			if f.Signed {
				gotSign = "i"
			}
			if !known || n != bytes || f.Size != bytes || f.Offset != offset || gotSign != wantSign || (explicit != "" && explicit != gotSign) || sign != fmt.Sprintf("[%d]%s8", n, wantSign) {
				return []string{fmt.Sprintf("tracepoint %s field %s declaration %q at offset %d, %d bytes, signed %t does not match offset %d, %d bytes, %s", event, field, f.Declaration, f.Offset, f.Size, f.Signed, offset, bytes, sign)}
			}
			return nil
		}
		if sign == "strptr" || sign == "strarray" {
			depth, known := tpCharPointerDepth(f)
			wantDepth := 1
			if sign == "strarray" {
				wantDepth = 2
			}
			if f.Offset != offset || f.Size != bytes || bytes != 8 || !known || depth != wantDepth {
				return []string{fmt.Sprintf("tracepoint %s field %s declaration %q at offset %d, %d bytes does not match offset %d, 8-byte char pointer %s", event, field, f.Declaration, f.Offset, f.Size, offset, sign)}
			}
			return nil
		}
		got := "u"
		if f.Signed {
			got = "i"
		}
		if f.Offset != offset || f.Size != bytes || got != sign {
			return []string{fmt.Sprintf("tracepoint %s field %s is at offset %d, %d bytes, %s in the target's tracefs format, but the object reads offset %d, %d bytes, %s",
				event, field, f.Offset, f.Size, got, offset, bytes, sign)}
		}
		return nil
	}
	return []string{fmt.Sprintf("tracepoint %s has no field %s in the target's tracefs format", event, field)}
}

// CheckTracepointField reads tracefs format. Unreadable/missing tracefs or
// events (including module events) yield blocking tpfield_unknown; mode 0700
// prevents non-root reads on the measured host. Non-root loaders can use
// recorded root caps; see docs/nonroot.md.
func (LiveCaps) CheckTracepointField(event, field string, offset, bytes int, sign string) ([]string, error) {
	cat, name, ok := strings.Cut(event, "/")
	if !ok || cat == "" || name == "" || strings.Contains(name, "/") || strings.Contains(event, "..") {
		return nil, unknownf("tracepoint %q is not <category>/<event>", event)
	}
	var errs []string
	for _, root := range tracefsRoots {
		b, err := os.ReadFile(filepath.Join(root, "events", cat, name, "format"))
		if err != nil {
			errs = append(errs, err.Error())
			continue
		}
		fields, err := ParseTracepointFormat(string(b))
		if err != nil {
			return nil, unknownf("%s: %v", event, err)
		}
		if sign == "strptr" || sign == "strarray" || strings.HasPrefix(sign, "[") {
			for _, f := range fields {
				if f.Name == field {
					_, known := tpCharPointerDepth(f)
					if strings.HasPrefix(sign, "[") {
						_, _, known = tpByteArrayShape(f)
					}
					if !known {
						return nil, unknownf("tracepoint %s field %s has an unknown declaration %q", event, field, f.Declaration)
					}
				}
			}
		}
		return CompareTracepointField(event, fields, field, offset, bytes, sign), nil
	}
	return nil, unknownf("the tracefs format of %s is not readable (%s) — tracefs needs root (a non-root loader uses caps recorded as root with a live re-probe — ebpf-precheck --caps --live), and a missing or module event is not checked", event, strings.Join(errs, "; "))
}

// isIntSpelling recognizes i8..u64.
func isIntSpelling(s string) bool {
	switch s {
	case "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64":
		return true
	}
	return false
}

// describeRet returns void or describeParam spelling.
func describeRet(t btf.Type) string {
	if t == nil {
		return "void"
	}
	if _, ok := btf.UnderlyingType(t).(*btf.Void); ok {
		return "void"
	}
	return describeParam(t)
}

// compareProto shares count/return/argument checks for struct_ops and ext.
// what supplies the diagnostic subject. Args are struct-pointer names, integers
// or '-' (skip). nargs<0 and empty ret skip their respective checks.
func compareProto(what string, proto *btf.FuncProto, nargs int, ret string, args []string) []string {
	var out []string
	if nargs >= 0 && len(proto.Params) != nargs {
		out = append(out, fmt.Sprintf("%s takes %d arguments in the target BTF, but the object declares %d", what, len(proto.Params), nargs))
	}
	if ret != "" {
		if got := describeRet(proto.Return); got != ret {
			out = append(out, fmt.Sprintf("%s returns %s in the target BTF, but the object declares %s", what, got, ret))
		}
	}
	for i, want := range args {
		if want == "-" {
			continue
		}
		if i >= len(proto.Params) {
			out = append(out, fmt.Sprintf("%s has no argument %d in the target BTF (it takes %d)", what, i, len(proto.Params)))
			continue
		}
		p := proto.Params[i]
		// enum:<bits> matches a BTF ENUM / ENUM64 of that size; the sign
		// (ENUM kflag) is not part of the contract and is not compared.
		if bits, ok := strings.CutPrefix(want, requirements.EnumArgPrefix); ok {
			if got := describeParam(p.Type); got != "enum"+bits {
				out = append(out, fmt.Sprintf("argument %d (%s) of %s is %s in the target BTF, but the object reads it as %s", i, requirements.ArgName(p.Name), what, got, want))
			}
			continue
		}
		if isIntSpelling(want) {
			if got := describeParam(p.Type); got != want {
				out = append(out, fmt.Sprintf("argument %d (%s) of %s is %s in the target BTF, but the object reads it as %s", i, requirements.ArgName(p.Name), what, got, want))
			}
			continue
		}
		pt, isPtr := btf.UnderlyingType(p.Type).(*btf.Pointer)
		if !isPtr {
			out = append(out, fmt.Sprintf("argument %d (%s) of %s is %s in the target BTF, not a pointer to struct %s", i, requirements.ArgName(p.Name), what, describeParam(p.Type), want))
			continue
		}
		if st, isStruct := btf.UnderlyingType(pt.Target).(*btf.Struct); !isStruct || st.Name != want {
			out = append(out, fmt.Sprintf("argument %d (%s) of %s points to %s in the target BTF, not struct %s", i, requirements.ArgName(p.Name), what, pt.Target, want))
		}
	}
	return out
}

// CheckStructOpsMember checks vmlinux struct_ops member signatures. Unreadable
// BTF or missing bpf_struct_ops_<struct> (e.g. a module type) is blocking Unknown.
func (LiveCaps) CheckStructOpsMember(strct, member string, nargs int, ret string, args []string) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, unknownf("reading the target BTF failed (%v)", err)
	}
	return CheckStructOpsMemberSpec(spec, strct, member, nargs, ret, args)
}

// CheckStructOpsMemberSpec is CheckStructOpsMember against a given kernel BTF,
// such as a vmlinux file of another kernel read offline.
func CheckStructOpsMemberSpec(spec *btf.Spec, strct, member string, nargs int, ret string, args []string) ([]string, error) {
	var value *btf.Struct
	if err := btfexact.TypeByName(spec, "bpf_struct_ops_"+strct, &value); err != nil {
		return nil, unknownf("bpf_struct_ops_%s is not in vmlinux BTF (%v) — a module struct_ops is not checked", strct, err)
	}
	var st *btf.Struct
	if err := btfexact.TypeByName(spec, strct, &st); err != nil {
		return nil, unknownf("struct %s is not in vmlinux BTF (%v)", strct, err)
	}
	for _, m := range st.Members {
		if m.Name != member {
			continue
		}
		pt, ok := btf.UnderlyingType(m.Type).(*btf.Pointer)
		if !ok {
			return []string{fmt.Sprintf("member %s of struct %s is %s in the target BTF, not a function pointer", member, strct, describeParam(m.Type))}, nil
		}
		proto, ok := btf.UnderlyingType(pt.Target).(*btf.FuncProto)
		if !ok {
			return []string{fmt.Sprintf("member %s of struct %s points to %s in the target BTF, not a function", member, strct, pt.Target)}, nil
		}
		return compareProto(fmt.Sprintf("struct_ops member %s.%s", strct, member), proto, nargs, ret, args), nil
	}
	return []string{fmt.Sprintf("struct %s has no member %s in the target BTF", strct, member)}, nil
}

// LoadExtTargetSpec reads replacement BTF from an ELF object or prog-id:<id>.
// Accessing a loaded program through BPF_PROG_GET_FD_BY_ID needs privileges.
func LoadExtTargetSpec(target string) (*btf.Spec, error) {
	if s, ok := strings.CutPrefix(target, "prog-id:"); ok {
		id, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("--ext-target %q: bad program id", target)
		}
		prog, err := ebpf.NewProgramFromID(ebpf.ProgramID(id))
		if err != nil {
			return nil, fmt.Errorf("program %d: %w", id, err)
		}
		defer prog.Close()
		info, err := prog.Info()
		if err != nil {
			return nil, fmt.Errorf("program %d info: %w", id, err)
		}
		bid, ok := info.BTFID()
		if !ok {
			return nil, fmt.Errorf("program %d has no BTF", id)
		}
		h, err := btf.NewHandleFromID(bid)
		if err != nil {
			return nil, fmt.Errorf("program %d BTF %d: %w", id, bid, err)
		}
		defer h.Close()
		return h.Spec(nil)
	}
	return btf.LoadSpec(target)
}

// CheckExtTargetBTF requires a global FUNC fn and matching count/types/return.
// Nil BTF or missing FUNC is blocking ext_target_unknown.
func CheckExtTargetBTF(spec *btf.Spec, fn string, nargs int, ret string, args []string) ([]string, error) {
	if spec == nil {
		return nil, fmt.Errorf("no BTF for the replacement target: %w", requirements.ErrUnknown)
	}
	var f *btf.Func
	if err := btfexact.TypeByName(spec, fn, &f); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return nil, fmt.Errorf("function %s is not in the replacement target's BTF: %w", fn, requirements.ErrUnknown)
		}
		return nil, fmt.Errorf("looking up %s in the replacement target's BTF (%v): %w", fn, err, requirements.ErrUnknown)
	}
	var out []string
	if f.Linkage != btf.GlobalFunc {
		out = append(out, fmt.Sprintf("function %s has linkage %v in the replacement target, not global (ext replaces only global functions)", fn, f.Linkage))
	}
	proto, ok := f.Type.(*btf.FuncProto)
	if !ok {
		return append(out, fmt.Sprintf("function %s has no FUNC_PROTO in the replacement target", fn)), nil
	}
	return append(out, compareProto("function "+fn, proto, nargs, ret, args)...), nil
}
