package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"strings"
)

// tp_btf and CO-RE kernel struct fields (bpf-mlir's ebpf.ctx.arg and ebpf.kfield.load), extended with kfield.copy, kfield.ptr and integer arguments:
//
//	type Task struct { _ bpf.Kernel `kernel:"task_struct"`; Pid int32 `kernel:"pid"`; Start uint64 `kernel:"start_time"`;
//	                   Comm [16]byte `kernel:"comm"`; MM *MM `kernel:"mm"` }                    → the schema's core.kernel_types (local types)
//	parent := bpf.TPArg[Task](ctx, 0)   → %k = ebpf.ctx.arg %ctx[0] : !ebpf.ctx<"tp_btf"> -> !ebpf.kptr<"task_struct">
//	parent.Pid / parent.Start           → ebpf.kfield.load %k "pid" : … -> i32 / "start_time" … -> i64 (8 to 64 bit)
//	q.Comm = parent.Comm                → ebpf.kfield.copy %k "comm", %borrow "comm" (q is a checked record pointer)
//	if m := parent.MM; m != nil { … }   → ebpf.kfield.ptr (kptr_or_null) + ebpf.kptr.check present(%m: kptr) / absent
//	sk.Common.Daddr (Common SockCommon `kernel:"__sk_common"` — a kernel type by value) → ebpf.kfield.load %k "__sk_common.skc_daddr" (a path of 1 to 3 segments, the four reads)
//	if p := bpf.TPArg[T](ctx, i); p != nil { … }    → schema argument i becomes nullable, ctx.arg → kptr_or_null + kptr.check
//	x := bpf.TPArgInt[uint32](ctx, 3)   → ebpf.ctx.arg %ctx[3] : !ebpf.ctx<"tp_btf"> -> i32 (an integer argument)
//	if p := bpf.FentryArg[T](ctx, i); p != nil { … } → fentry's ctx.arg (always kptr_or_null) + kptr.check, the schema's fentry args (the farg requirement)
//
// The schema's args are a positional array (0..max i) — unread arguments are null. The target check (precheck) checks each against the target.

// kfKind is the kind of a local type field.
type kfKind int

const (
	kfInt    kfKind = iota // an integer (8 to 64 bit) — kfield.load
	kfArray                // an 8-bit integer array [N] (1 ≤ N ≤ 64) — kfield.copy
	kfPtr                  // a pointer to a local type — kfield.ptr (always possibly NULL)
	kfStrPtr               // a char * string (bpf.KernelStr) — only in kernel.read_str of RingBuf.OutputKernelStr
	kfStruct               // a local type embedded by value — only a step of a field path p.A.F (the schema's struct)
)

// maxKernelPath is the number of segments of a kernel field path p.A.B.F (bpf-mlir's limit — 1 to 3).
const maxKernelPath = 3

// maxKernelCopy is the upper bound of the kfield.copy array length (bpf-mlir's limit).
const maxKernelCopy = 64

// KernelType is a local declaration of a kernel struct (the schema's core.kernel_types).
type KernelType struct {
	Name   string // the kernel struct name (tag)
	GoType *types.Named
	Fields []KernelField
	Pos    token.Position
	Note   string // the schema note of a builtin local type (the iter note if empty)
}

// KernelField is a field of a local type.
type KernelField struct {
	Name, GoName string
	Kind         kfKind
	Bits         int  // kfInt
	Signed       bool // kfInt, the kfArray element
	Count        int  // kfArray
	Target       *KernelType
}

// kernelTypeOf turns t (a type argument of TPArg / FentryArg, or the element type of a pointer field) into a kernel local type. Errors are reported as GB027 and it returns nil.
func (a *analyzer) kernelTypeOf(t types.Type, at token.Pos) *KernelType {
	named, _ := t.(*types.Named)
	var st *types.Struct
	if named != nil {
		st, _ = named.Underlying().(*types.Struct)
	}
	if st == nil || named.Obj().Pkg() != a.pkg.Types {
		a.report(Rejected, GB027KernelTypeShape, at, nil, "the type argument of bpf.TPArg must be a kernel struct declared in this package (a named struct with a blank `_ bpf.Kernel` field tagged `kernel:\"<struct>\"`), got %s", a.typeString(t))
		return nil
	}
	if kt, done := a.kernelTypes[named]; done {
		return kt
	}
	kt := &KernelType{GoType: named, Pos: a.position(named.Obj().Pos())}
	a.kernelTypes[named] = kt // a pointer field referring to itself (real_parent of task_struct) — returns the partial kt; reset to nil below on error
	good := true
	bad := func(p token.Pos, format string, args ...any) {
		a.report(Rejected, GB027KernelTypeShape, p, []string{named.Obj().Name()}, format, args...)
		good = false
	}
	for i := 0; i < st.NumFields(); i++ {
		f := st.Field(i)
		tag, hasTag := reflect.StructTag(st.Tag(i)).Lookup("kernel")
		if f.Name() == "_" && isBPFNamed(f.Type(), "Kernel") {
			if kt.Name != "" {
				bad(f.Pos(), "kernel type %s has two bpf.Kernel marks", named.Obj().Name())
				continue
			}
			if !hasTag || tag == "" {
				bad(f.Pos(), "the bpf.Kernel mark of %s needs the kernel struct's name as `kernel:\"<struct>\"`", named.Obj().Name())
				continue
			}
			kt.Name = tag
			continue
		}
		kf, ok := a.kernelFieldOf(f.Type(), f.Pos())
		if !ok {
			if good {
				bad(f.Pos(), "kernel type %s: field %s has type %s — a kernel field is int8 to int64 / uint8 to uint64, [N]byte / [N]int8 (1 ≤ N ≤ %d — copied with q.F = p.F), *U of a kernel type U (read with `if m := p.F; m != nil { … }`), or a kernel type U by value (an embedded struct — read through p.F.G)", named.Obj().Name(), f.Name(), a.typeString(f.Type()), maxKernelCopy)
			}
			good = false
			continue
		}
		if !f.Exported() || !hasTag || tag == "" {
			bad(f.Pos(), "kernel type %s: field %s needs to be exported and tagged `kernel:\"<field>\"` (the kernel field's name)", named.Obj().Name(), f.Name())
			continue
		}
		kf.Name, kf.GoName = tag, f.Name()
		kt.Fields = append(kt.Fields, kf)
	}
	if kt.Name == "" && good {
		bad(named.Obj().Pos(), "%s is not a kernel type — add a blank field _ bpf.Kernel tagged kernel:\"<struct>\" (the kernel struct's name)", named.Obj().Name())
	}
	if len(kt.Fields) == 0 && good {
		bad(named.Obj().Pos(), "kernel type %s declares no fields to read", named.Obj().Name())
	}
	if !good {
		a.kernelTypes[named] = nil
		return nil
	}
	for _, other := range a.kernelOrder {
		if other.Name == kt.Name && other.GoType != named {
			bad(named.Obj().Pos(), "kernel struct %s is declared twice (%s and %s) — one local type per kernel struct", kt.Name, other.goName(), named.Obj().Name())
			a.kernelTypes[named] = nil
			return nil
		}
	}
	a.kernelOrder = append(a.kernelOrder, kt)
	return kt
}

// kernelFieldOf returns the type of a local type field (an integer, an 8-bit array, a pointer to a local type). An error in the pointer element type was reported by kernelTypeOf, giving false.
func (a *analyzer) kernelFieldOf(t types.Type, at token.Pos) (KernelField, bool) {
	if n, ok := t.(*types.Named); ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == bpfPkg && n.Obj().Name() == "KernelStr" {
		return KernelField{Kind: kfStrPtr}, true // the schema's strptr
	}
	if it, ok := intTypeOf(t); ok {
		return KernelField{Kind: kfInt, Bits: it.Bits, Signed: it.Signed}, true
	}
	if arr, ok := t.Underlying().(*types.Array); ok {
		it, isInt := intTypeOf(arr.Elem())
		if !isInt || it.Bits != 8 || arr.Len() < 1 || arr.Len() > maxKernelCopy {
			return KernelField{}, false
		}
		return KernelField{Kind: kfArray, Count: int(arr.Len()), Signed: it.Signed}, true
	}
	if p, ok := t.(*types.Pointer); ok {
		if n, isNamed := p.Elem().(*types.Named); isNamed {
			if _, isStruct := n.Underlying().(*types.Struct); isStruct && n.Obj().Pkg() == a.pkg.Types {
				target := a.kernelTypeOf(n, at)
				return KernelField{Kind: kfPtr, Target: target}, target != nil
			}
		}
	}
	if n, isNamed := t.(*types.Named); isNamed { // a local type embedded by value (Go rejects value cycles)
		if _, isStruct := n.Underlying().(*types.Struct); isStruct && n.Obj().Pkg() == a.pkg.Types {
			target := a.kernelTypeOf(n, at)
			return KernelField{Kind: kfStruct, Target: target}, target != nil
		}
	}
	return KernelField{}, false
}

// fieldByGoName looks up a local type field by its Go name.
func (kt *KernelType) fieldByGoName(name string) *KernelField {
	for i := range kt.Fields {
		if kt.Fields[i].GoName == name {
			return &kt.Fields[i]
		}
	}
	return nil
}

// tpArgDecl is the declaration of argument i of a tp_btf / fentry program (one of the schema's args).
type tpArgDecl struct {
	kt       *KernelType // the struct pointer (nil for an integer)
	it       *IntType    // an integer argument (TPArgInt)
	nullable bool        // a possibly NULL argument read in the tp_btf check shape
	pos      token.Pos
}

func (d tpArgDecl) String() string {
	switch {
	case d.it != nil:
		return d.it.mlir()
	case d.nullable:
		return "nullable " + d.kt.Name
	}
	return d.kt.Name
}

// schemaArg returns one of the schema's args (a struct name, a nullable object, an integer type).
func (d tpArgDecl) schemaArg() any {
	switch {
	case d.it != nil:
		return schemaIntOf(*d.it)
	case d.nullable:
		return map[string]any{"kind": "struct", "name": d.kt.Name, "nullable": true}
	}
	return d.kt.Name
}

// isTPArgCall reports whether e is a call of bpf.TPArg[T](…).
func (l *lowerer) isTPArgCall(e ast.Expr) (*ast.CallExpr, bool) {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	return call, l.callOp(call) == "tp_arg"
}

// ctxArgOf reads the arguments (the context, a constant index 0..11) and type argument of a bpf.TPArg / TPArgInt / FentryArg call. On error it has reported and ok is false.
func (l *lowerer) ctxArgOf(call *ast.CallExpr, fn string) (int, types.Type, bool) {
	if l.calleeAttach(call.Pos(), "bpf."+fn) { // stops in a callee (declareArg writes the program's declaration)
		return 0, nil, false
	}
	if cid, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[cid] != l.ctxVar {
		l.fail(Rejected, GB027KernelTypeShape, call.Args[0].Pos(), "the first argument of bpf.%s must be the program's context parameter", fn)
		return 0, nil, false
	}
	tv := l.a.info.Types[call.Args[1]]
	i, exact := int64(-1), false
	if tv.Value != nil {
		i, exact = constant.Int64Val(constant.ToInt(tv.Value))
	}
	if !exact || i < 0 || i > 11 {
		what := "a tracepoint"
		if fn == "FentryArg" || fn == "FentryArgInt" || fn == "LSMArg" || fn == "LSMArgInt" || fn == "FmodRetArgInt" {
			what = "a function"
		}
		l.fail(Rejected, GB027KernelTypeShape, call.Args[1].Pos(), "the argument index of bpf.%s must be a constant 0..11 (%s has at most 12 arguments)", fn, what)
		return 0, nil, false
	}
	var targ types.Type
	// type argument 0 is the argument type (type argument 1 of LSMArg / LSMArgInt is the inferred context type).
	if inst, ok := l.a.info.Instances[tpArgIdent(call)]; ok && inst.TypeArgs != nil && inst.TypeArgs.Len() >= 1 {
		targ = inst.TypeArgs.At(0)
	}
	return int(i), targ, true
}

// declareArg records the declaration of argument i of the program (a different declaration of the same argument is GB027).
func (l *lowerer) declareArg(i int, d tpArgDecl) bool {
	p := l.prog
	if p.args == nil {
		p.args = map[int]tpArgDecl{}
	}
	if prev, seen := p.args[i]; seen {
		if prev.String() != d.String() {
			if prev.kt != nil && d.kt != nil && prev.nullable == d.nullable {
				l.fail(Rejected, GB027KernelTypeShape, d.pos, "argument %d of the %s program %s is declared as %s here but as %s at %s — one argument has one kernel type", i, p.ProgramType, p.Symbol, d.kt.Name, prev.kt.Name, posString(l.a.position(prev.pos)))
			} else {
				l.fail(Rejected, GB027KernelTypeShape, d.pos, "argument %d of the %s program %s is read as %s here but as %s at %s — read one argument one way (a NULL-able argument only with `if p := bpf.TPArg[T](ctx, i); p != nil { … }`)", i, p.ProgramType, p.Symbol, d, prev, posString(l.a.position(prev.pos)))
			}
			return false
		}
		return true
	}
	p.args[i] = d
	return true
}

// tpArgAssign lowers top-level `p := bpf.TPArg[T](ctx, i)` / `_ = bpf.TPArg[T](ctx, j)` / `x := bpf.TPArgInt[T](ctx, i)` of the body.
// handled reports whether s has that shape (or the unchecked FentryArg shape stopped here).
func (l *lowerer) tpArgAssign(s *ast.AssignStmt) bool {
	if len(s.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	op := l.callOp(call)
	if op == "fentry_arg" || op == "lsm_arg" || op == "structops_arg" { // also structops_arg
		fn := map[string]string{"fentry_arg": "FentryArg", "lsm_arg": "LSMArg", "structops_arg": "StructOpsArg"}[op]
		l.fail(Rejected, GB005NilCheckShape, call.Pos(), "bpf.%s returns a pointer that may be NULL — read it only as `if p := bpf.%s[T](ctx, i); p != nil { … }`", fn, fn)
		return true
	}
	if op != "tp_arg" && op != "tp_arg_int" && op != "fentry_arg_int" && op != "lsm_arg_int" && op != "fmod_ret_arg_int" && op != "structops_arg_int" {
		return false
	}
	fn := map[string]string{"tp_arg": "TPArg", "tp_arg_int": "TPArgInt", "fentry_arg_int": "FentryArgInt", "lsm_arg_int": "LSMArgInt", "fmod_ret_arg_int": "FmodRetArgInt", "structops_arg_int": "StructOpsArgInt"}[op]
	defer l.at(s.Pos())()
	if fn == "StructOpsArgInt" { // an integer argument of a struct_ops member
		if l.progKind == nil || l.progKind.Kind != "struct_ops" || l.prog == nil {
			l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "bpf.StructOpsArgInt may only be used in the body of a struct_ops program (func f(ctx *bpf.StructOpsContext) … with //gobpf:struct_ops <map> <member>)")
			return true
		}
	} else if fn == "FentryArgInt" { // an integer argument of fentry
		if l.progKind == nil || l.progKind.Kind != "fentry" || l.prog == nil {
			l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "bpf.FentryArgInt may only be used in the body of a fentry program (func f(ctx *bpf.FentryContext) with //gobpf:fentry <function>)")
			return true
		}
	} else if fn == "FmodRetArgInt" { // an integer argument of the fmod_ret function
		if l.progKind == nil || l.progKind.Kind != "fmod_ret" || l.prog == nil {
			l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "bpf.FmodRetArgInt may only be used in the body of a fmod_ret program (func f(ctx *bpf.FmodRetContext) bpf.FmodRet with //gobpf:fmod_ret <function> nargs=<N>)")
			return true
		}
	} else if fn == "LSMArgInt" { // an integer argument of the lsm hook
		if l.progKind == nil || !isLSMKind(l.progKind.Kind) || l.prog == nil {
			l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "bpf.LSMArgInt may only be used in the body of a lsm program (func f(ctx *bpf.LSMContext) bpf.LSMRet with //gobpf:lsm <hook>, or lsm_s)")
			return true
		}
	} else if l.progKind == nil || l.progKind.Kind != "tp_btf" || l.prog == nil {
		l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "bpf.%s may only be used in the body of a tp_btf program (func f(ctx *bpf.TPBTFContext) with //gobpf:tp_btf <tracepoint>)", fn)
		return true
	}
	ctxKind := l.progKind.Kind
	top := false
	for _, st := range l.fnBody.List {
		if st == ast.Stmt(s) {
			top = true
		}
	}
	id, _ := s.Lhs[0].(*ast.Ident)
	blank := id != nil && id.Name == "_" && s.Tok == token.ASSIGN
	if !top || len(s.Lhs) != 1 || id == nil || !(blank || s.Tok == token.DEFINE) {
		if fn == "TPArg" {
			l.fail(Rejected, GB027KernelTypeShape, s.Pos(), "bpf.TPArg must be a top-level statement of the tp_btf program body, `p := bpf.TPArg[T](ctx, i)` (or `_ = bpf.TPArg[T](ctx, i)` to declare the type of an argument it does not read), or the nil check of a NULL-able argument `if p := bpf.TPArg[T](ctx, i); p != nil { … }`")
		} else {
			l.fail(Rejected, GB027KernelTypeShape, s.Pos(), "bpf.%s must be a top-level statement of the %s program body, `x := bpf.%s[T](ctx, i)`", fn, ctxKind, fn)
		}
		return true
	}
	i, targ, ok := l.ctxArgOf(call, fn)
	if !ok {
		return true
	}
	if fn == "TPArgInt" || fn == "FentryArgInt" || fn == "LSMArgInt" || fn == "FmodRetArgInt" || fn == "StructOpsArgInt" {
		it, isInt := intTypeOf(targ)
		if !isInt {
			l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "the type argument of bpf.%s must be an integer type int8 to uint64, got %s", fn, l.a.typeString(targ))
			return true
		}
		if fn == "StructOpsArgInt" && !l.structOpsArgOK(call.Pos(), i, nil, &it) { // an argument in the member table
			return true
		}
		if !l.declareArg(i, tpArgDecl{it: &it, pos: call.Pos()}) || blank {
			return true
		}
		v, _ := l.a.info.Defs[id].(*types.Var)
		if v == nil {
			l.fail(Rejected, GB027KernelTypeShape, id.Pos(), "`%s := bpf.%s…` must declare a new variable", id.Name, fn)
			return true
		}
		r := l.val()
		l.emit("%s = ebpf.ctx.arg %%ctx[%d] : !ebpf.ctx<%q> -> %s", r, i, ctxKind, it.mlir())
		l.env[v] = value{r, vtypeOf(it)}
		return true
	}
	kt := l.a.kernelTypeOf(targ, call.Pos())
	if kt == nil {
		l.failed = true
		return true
	}
	if !l.declareArg(i, tpArgDecl{kt: kt, pos: call.Pos()}) || blank {
		return true // only a type declaration (the schema's args) — ctx.arg is Pure, so not emitted
	}
	v, _ := l.a.info.Defs[id].(*types.Var)
	if v == nil {
		l.fail(Rejected, GB027KernelTypeShape, id.Pos(), "`%s := bpf.TPArg…` must declare a new variable", id.Name)
		return true
	}
	if !l.a.checkKptrUses(l.fnBody, v, kt, false) {
		l.failed = true
		return true
	}
	r := l.val()
	l.emit("%s = ebpf.ctx.arg %%ctx[%d] : !ebpf.ctx<\"tp_btf\"> -> !ebpf.kptr<%q>", r, i, kt.Name)
	l.bindKptr(v, r, kt)
	return true
}

func (l *lowerer) bindKptr(v *types.Var, name string, kt *KernelType) {
	if l.kptrs == nil {
		l.kptrs = map[*types.Var]kptrVal{}
	}
	l.kptrs[v] = kptrVal{name: name, kt: kt}
}

// tpArgIdent returns the function identifier of bpf.TPArg[T](…) / bpf.TPArg(…) (the key into Instances).
func tpArgIdent(call *ast.CallExpr) *ast.Ident {
	fun := ast.Unparen(call.Fun)
	if ix, ok := fun.(*ast.IndexExpr); ok {
		fun = ix.X
	}
	if sel, ok := fun.(*ast.SelectorExpr); ok {
		return sel.Sel
	}
	id, _ := fun.(*ast.Ident)
	return id
}

type kptrVal struct {
	name string
	kt   *KernelType
}

// checkKptrUses checks that every use of a kernel pointer variable v is a field read (`v.F` — not an assignment left-hand side, ++ / --, or inside &) (GB027).
// writable is for struct_ops member arguments — it accepts `v.F = x` (an = assignment with one left-hand side) (kptrStore in lowering checks for an integer field).
func (a *analyzer) checkKptrUses(body ast.Node, v *types.Var, kt *KernelType, writable bool) bool {
	good := true
	walkWithStack(body, func(n ast.Node, stack []ast.Node) {
		id, ok := n.(*ast.Ident)
		if !ok || a.info.Uses[id] != v {
			return
		}
		if call, isCall := parent(stack, 1).(*ast.CallExpr); isCall && (a.isStorageOwnerArg(call, id) || a.isKernelAddrArg(call, id)) {
			return // a local storage owner (the kptr argument of storage.get / delete) or bpf.KernelAddr's argument
		}
		sel, isSel := parent(stack, 1).(*ast.SelectorExpr)
		if !isSel || sel.X != ast.Expr(id) {
			what := "used as a value"
			switch p := parent(stack, 1).(type) {
			case *ast.BinaryExpr:
				if p.Op == token.EQL || p.Op == token.NEQ {
					what = "compared (a checked kernel pointer is never nil — a NULL-able argument is read as `if p := bpf.TPArg[T](ctx, i); p != nil { … }`, a pointer field as `if m := p.F; m != nil { … }`)"
				}
			case *ast.StarExpr:
				what = "dereferenced as a whole (*p copies the kernel struct)"
			case *ast.CallExpr:
				what = "passed to a function"
			case *ast.AssignStmt:
				what = "assigned"
			}
			a.report(Rejected, GB027KernelTypeShape, id.Pos(), nil, "the kernel pointer %s is %s — it may only be read field by field (%s.F)", id.Name, what, id.Name)
			good = false
			return
		}
		top, k := ast.Expr(sel), 2 // the whole field path p.F / p.A.F (embedded structs)
		for {
			ps, isPS := parent(stack, k).(*ast.SelectorExpr)
			if !isPS || ps.X != top {
				break
			}
			top, k = ps, k+1
		}
		x := types.ExprString(top)
		switch p := parent(stack, k).(type) {
		case *ast.AssignStmt:
			for _, lh := range p.Lhs {
				if lh == top {
					switch {
					case writable && top != ast.Expr(sel):
						a.report(Rejected, GB027KernelTypeShape, top.Pos(), nil, "the kernel struct field path %s cannot be written — a struct_ops program writes only a field of the argument itself (`%s.F = x` — bpf-mlir's kfield.store takes one segment)", x, id.Name)
					case writable && p.Tok == token.ASSIGN && len(p.Lhs) == 1 && len(p.Rhs) == 1:
						continue // struct_ops `sk.F = x` (kfield.store)
					case writable:
						a.report(Rejected, GB027KernelTypeShape, top.Pos(), nil, "the kernel struct field %s may only be written by a plain assignment `%s = x` (one left side, =)", x, x)
					default:
						a.report(Rejected, GB027KernelTypeShape, top.Pos(), nil, "the kernel struct field %s cannot be written — kernel pointers are read-only", x)
					}
					good = false
				}
			}
		case *ast.IncDecStmt:
			a.report(Rejected, GB027KernelTypeShape, top.Pos(), nil, "the kernel struct field %s cannot be written — kernel pointers are read-only", x)
			good = false
		case *ast.UnaryExpr:
			if p.Op == token.AND {
				a.report(Rejected, GB027KernelTypeShape, p.Pos(), nil, "the address of the kernel struct field %s cannot be taken", x)
				good = false
			}
		}
	})
	return good
}

// isKernelAddrArg reports whether e is the argument of bpf.KernelAddr (kernelAddr checks its shape when lowering).
func (a *analyzer) isKernelAddrArg(call *ast.CallExpr, e ast.Expr) bool {
	if len(call.Args) != 1 || call.Args[0] != e {
		return false
	}
	fun := ast.Unparen(call.Fun)
	if ix, ok := fun.(*ast.IndexExpr); ok {
		fun = ix.X
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj := a.info.Uses[sel.Sel]
	if obj == nil || !inAPIPackage(obj) {
		return false
	}
	en, known := lookupAPI(obj)
	return known && en.op == "kernel_addr"
}

// kernelAddrKinds are the program kinds whose bodies may take a kernel pointer's address (bpf-mlir's kptr.addr).
var kernelAddrKinds = map[string]bool{"tp_btf": true, "fentry": true, "fexit": true, "iter": true, "fmod_ret": true, "fsession": true}

// kernelAddr lowers bpf.KernelAddr(p) (p a checked kernel pointer variable) to ebpf.kptr.addr — the 64 address bits as i64 (the pointee is not read).
func (l *lowerer) kernelAddr(call *ast.CallExpr) (value, bool) {
	arg := ast.Unparen(call.Args[0])
	if l.progKind == nil || l.prog == nil || !kernelAddrKinds[l.progKind.Kind] {
		l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "bpf.KernelAddr may only be used in the body of a tp_btf, fentry, fexit, iter, fmod_ret or fsession program (bpf-mlir's kptr.addr)")
		return value{}, false
	}
	if c, isCall := arg.(*ast.CallExpr); isCall {
		if op := l.callOp(c); op == "fentry_arg" || op == "tp_arg" || op == "lsm_arg" {
			l.fail(Rejected, GB005NilCheckShape, arg.Pos(), "the argument of bpf.KernelAddr may be NULL — check it first and pass the checked variable (`if p := bpf.FentryArg[T](ctx, i); p != nil { a := bpf.KernelAddr(p) }`)")
			return value{}, false
		}
	}
	if pk, sels, isPath := l.kpathOf(arg); isPath {
		x := types.ExprString(arg)
		if f, i := kpathLeaf(pk.kt, sels); f != nil && i == len(sels)-1 && f.Kind == kfPtr {
			l.fail(Rejected, GB005NilCheckShape, arg.Pos(), "the kernel pointer field %s may be NULL — pass the checked variable: `if m := %s; m != nil { a := bpf.KernelAddr(m) }`", x, x)
			return value{}, false
		}
		l.fail(Rejected, GB027KernelTypeShape, arg.Pos(), "the argument of bpf.KernelAddr must be a checked kernel pointer variable, got the field %s", x)
		return value{}, false
	}
	id, isID := arg.(*ast.Ident)
	var kp kptrVal
	found := false
	if isID {
		if v, _ := l.a.info.Uses[id].(*types.Var); v != nil {
			kp, found = l.kptrs[v]
		}
	}
	if !found {
		l.fail(Rejected, GB027KernelTypeShape, arg.Pos(), "the argument of bpf.KernelAddr must be a checked pointer of a local kernel type (from bpf.FentryArg / bpf.TPArg / a checked pointer field), got %s", types.ExprString(arg))
		return value{}, false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "bpf.KernelAddr cannot be used inside a loop (bpf-mlir does not allow kptr.addr in a loop body) — take the address before the loop")
		return value{}, false
	}
	defer l.at(call.Pos())()
	r := l.val()
	l.emit("%s = ebpf.kptr.addr %s : !ebpf.kptr<%q> -> i64", r, kp.name, kp.kt.Name)
	return value{r, vtypeOf(IntType{Bits: 64})}, true
}

// kpathOf splits a selector chain `p.F` / `p.A.F` / `p.A.B.F` (p a kernel pointer variable) into p and its selectors from p outwards. ok is false for any other shape.
func (l *lowerer) kpathOf(e ast.Expr) (kp kptrVal, sels []*ast.SelectorExpr, ok bool) {
	x := ast.Unparen(e)
	for {
		s, isSel := x.(*ast.SelectorExpr)
		if !isSel {
			break
		}
		sels = append([]*ast.SelectorExpr{s}, sels...)
		x = ast.Unparen(s.X)
	}
	id, isID := x.(*ast.Ident)
	if !isID || len(sels) == 0 {
		return kp, nil, false
	}
	v, _ := l.a.info.Uses[id].(*types.Var)
	kp, isK := l.kptrs[v]
	return kp, sels, v != nil && isK
}

// kpathLeaf follows the embedded struct steps of sels from kt. It returns the last field reached and its index in sels
// (the leaf, or the first step that is not an embedded struct; f is nil when a field is missing at index i).
func kpathLeaf(kt *KernelType, sels []*ast.SelectorExpr) (f *KernelField, i int) {
	for i = range sels {
		if f = kt.fieldByGoName(sels[i].Sel.Name); f == nil || f.Kind != kfStruct || i == len(sels)-1 {
			return f, i
		}
		kt = f.Target
	}
	return nil, 0
}

// kptrSel resolves `p.F`, or a field path `p.A.F` / `p.A.B.F` through embedded local types (p a kernel pointer variable — bpf-mlir's dotted kfield path of 1 to 3 segments).
// f is a copy of the leaf whose Name is the dotted path of kernel field names. handled reports whether e has that shape (on error it has reported and f is nil).
func (l *lowerer) kptrSel(e ast.Expr) (kp kptrVal, f *KernelField, sel *ast.SelectorExpr, handled bool) {
	kp, sels, ok := l.kpathOf(e)
	if !ok {
		return kp, nil, nil, false
	}
	sel = sels[len(sels)-1]
	leaf, i := kpathLeaf(kp.kt, sels)
	if leaf == nil {
		owner := kp.kt.goName()
		if i > 0 {
			owner = types.ExprString(sels[i-1])
		}
		l.fail(Rejected, GB027KernelTypeShape, sels[i].Sel.Pos(), "kernel type %s has no readable field %s", owner, sels[i].Sel.Name)
		return kp, nil, sel, true
	}
	if i < len(sels)-1 {
		step := types.ExprString(sels[i])
		if leaf.Kind == kfPtr {
			l.fail(Rejected, GB005NilCheckShape, sels[i].Pos(), "the kernel pointer field %s may be NULL — read it only as `if m := %s; m != nil { … m.F … }`", step, step)
		} else {
			l.fail(Rejected, GB027KernelTypeShape, sels[i].Pos(), "the kernel field %s is not an embedded kernel struct — only an embedded kernel type (a field of a kernel type U by value) is a step of a field path", step)
		}
		return kp, nil, sel, true
	}
	if len(sels) > maxKernelPath {
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel field path %s has %d segments — bpf-mlir reads a field path of 1 to %d segments", types.ExprString(sel), len(sels), maxKernelPath)
		return kp, nil, sel, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, sel.Pos(), "the kernel struct field %s cannot be read inside a loop (bpf-mlir does not allow kfield.load in a loop body) — read it before the loop", types.ExprString(sel))
		return kp, nil, sel, true
	}
	path := make([]string, 0, len(sels))
	kt := kp.kt
	for _, s := range sels {
		sf := kt.fieldByGoName(s.Sel.Name)
		path = append(path, sf.Name)
		kt = sf.Target
	}
	out := *leaf
	out.Name = strings.Join(path, ".")
	return kp, &out, sel, true
}

// kptrField lowers `p.F` (p a kernel pointer, F an integer) to ebpf.kfield.load. handled reports whether e has that shape.
func (l *lowerer) kptrField(e ast.Expr) (value, bool, bool) {
	kp, f, sel, handled := l.kptrSel(e)
	if !handled {
		return value{}, false, l.kptrChainMisuse(e)
	}
	if f == nil {
		return value{}, false, true
	}
	x := types.ExprString(sel)
	switch f.Kind {
	case kfArray:
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel array field %s can only be copied whole into a record field of the same type (`q.F = %s` — q a checked record pointer: ebpf.kfield.copy)", x, x)
		return value{}, false, true
	case kfPtr:
		l.fail(Rejected, GB005NilCheckShape, sel.Pos(), "the kernel pointer field %s may be NULL — read it only as `if m := %s; m != nil { … }`", x, x)
		return value{}, false, true
	case kfStrPtr:
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel string field %s (bpf.KernelStr) cannot be used as a value — pass it only as the second argument of RingBuf.OutputKernelStr (kernel.read_str)", x)
		return value{}, false, true
	case kfStruct:
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the embedded kernel struct %s cannot be read as a value — read its fields (%s.F)", x, x)
		return value{}, false, true
	}
	defer l.at(sel.Pos())()
	it := IntType{Bits: f.Bits, Signed: f.Signed}
	r := l.val()
	l.emit("%s = ebpf.kfield.load %s %q : !ebpf.kptr<%q> -> %s", r, kp.name, f.Name, kp.kt.Name, it.mlir())
	return value{r, vtypeOf(it)}, true, true
}

// kfieldCopy lowers `q.F = p.G` (q a checked record pointer, G a kernel [N]byte field) to ebpf.kfield.copy. handled reports whether s has that shape.
func (l *lowerer) kfieldCopy(s *ast.AssignStmt) bool {
	if s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	kp, f, sel, handled := l.kptrSel(s.Rhs[0])
	if !handled || f == nil || f.Kind != kfArray {
		return false
	}
	acc, ok, h := l.walkAccess(s.Lhs[0], true)
	if !h {
		l.fail(Rejected, GB027KernelTypeShape, s.Lhs[0].Pos(), "the kernel array field %s can only be copied into a field of a checked record pointer (`if q := M.Lookup(k); q != nil { q.F = %s }`)", types.ExprString(sel), types.ExprString(sel))
		return true
	}
	if !ok {
		return true
	}
	if len(acc.vars) > 0 || acc.end.Kind != ABIArray || acc.end.Array.Elem.Kind != ABIInt || acc.end.Array.Elem.Int.Bits != 8 || acc.end.Array.Count != uint64(f.Count) {
		l.fail(Rejected, GB027KernelTypeShape, s.Lhs[0].Pos(), "the destination of the kernel array copy must be a [%d]byte field at a constant path of the checked record (got %s)", f.Count, types.ExprString(s.Lhs[0]))
		return true
	}
	defer l.at(s.Pos())()
	l.emit("ebpf.kfield.copy %s %q, %s %q : !ebpf.kptr<%q>, %s", kp.name, f.Name, acc.ref.borrow, acc.path, kp.kt.Name, borrowType(acc.ref))
	return true
}

// kptrSource reports whether X of `if m := X; m != nil` is a possibly NULL kernel pointer (a pointer field, FentryArg, TPArg).
func (l *lowerer) kptrSource(e ast.Expr) string {
	if call, ok := ast.Unparen(e).(*ast.CallExpr); ok {
		switch l.callOp(call) {
		case "fentry_arg":
			return "fentry"
		case "tp_arg":
			return "tp_btf"
		case "lsm_arg":
			return "lsm" // lsm and lsm_s
		case "iter_seq":
			return "iter" // ctx.Seq() (the seq of bpf_iter_meta)
		case "structops_arg":
			return "struct_ops" // a struct argument of a member
		}
		return ""
	}
	if kp, sels, ok := l.kpathOf(e); ok { // p.F or a field path p.A.F (kptrSel reports a path that is too long)
		if f, i := kpathLeaf(kp.kt, sels); f != nil && i == len(sels)-1 && f.Kind == kfPtr {
			return "field"
		}
	}
	return ""
}

// isKptrCheckIf reports whether s is `if m := <a possibly NULL kernel pointer>; …`.
func (l *lowerer) isKptrCheckIf(s *ast.IfStmt) bool {
	as, ok := s.Init.(*ast.AssignStmt)
	return ok && len(as.Rhs) == 1 && l.kptrSource(as.Rhs[0]) != ""
}

// kptrCheckIf lowers `if m := X; m != nil { … } [else { … }]` to ebpf.kptr.check (in the present arm m is a non-NULL kernel pointer).
func (l *lowerer) kptrCheckIf(s *ast.IfStmt) {
	as := s.Init.(*ast.AssignStmt)
	src := l.kptrSource(as.Rhs[0])
	form := map[string]string{"field": "if m := p.F; m != nil { … }", "fentry": "if p := bpf.FentryArg[T](ctx, i); p != nil { … }", "tp_btf": "if p := bpf.TPArg[T](ctx, i); p != nil { … }",
		"lsm": "if p := bpf.LSMArg[T](ctx, i); p != nil { … }", "iter": "if s := ctx.Seq(); s != nil { … }", "struct_ops": "if sk := bpf.StructOpsArg[T](ctx, 0); sk != nil { … }"}[src]
	shape := func(p token.Pos, what string) {
		l.fail(Rejected, GB005NilCheckShape, p, "%s — the supported form is `%s [else { … }]`", what, form)
	}
	mid, _ := as.Lhs[0].(*ast.Ident)
	if as.Tok != token.DEFINE || len(as.Lhs) != 1 || mid == nil || mid.Name == "_" {
		shape(as.Pos(), "the if statement's init must declare one variable")
		return
	}
	mobj, _ := l.a.info.Defs[mid].(*types.Var)
	if !l.isNilCheck(s.Cond, mobj) {
		shape(s.Cond.Pos(), fmt.Sprintf("the condition must be exactly `%s != nil`", mid.Name))
		return
	}
	var elseBlock *ast.BlockStmt
	if s.Else != nil {
		eb, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			shape(s.Else.Pos(), "else-if is not supported")
			return
		}
		elseBlock = eb
		l.rejectUses(eb, mobj, "the kernel pointer is NULL in the else branch")
		if l.failed {
			return
		}
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "a kernel pointer cannot be checked inside a loop (bpf-mlir does not allow kfield / ctx.arg of kernel pointers in a loop body) — check it before the loop")
		return
	}
	defer l.at(s.Pos())()
	var kt *KernelType
	src2 := l.val()
	switch src {
	case "field":
		kp, f, _, _ := l.kptrSel(as.Rhs[0])
		if f == nil {
			return
		}
		kt = f.Target
		l.emit("%s = ebpf.kfield.ptr %s %q : !ebpf.kptr<%q> -> !ebpf.kptr_or_null<%q>", src2, kp.name, f.Name, kp.kt.Name, kt.Name)
	case "iter": // ctx.Seq(): the seq of bpf_iter_meta
		if !l.iterPlace(ast.Unparen(as.Rhs[0]).(*ast.CallExpr)) {
			return
		}
		m, _, seq := l.iterMeta()
		kt = seq
		l.emit("%s = ebpf.kfield.ptr %s \"seq\" : !ebpf.kptr<\"bpf_iter_meta\"> -> !ebpf.kptr_or_null<\"seq_file\">", src2, m)
	default:
		call := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		fn := map[string]string{"fentry": "FentryArg", "tp_btf": "TPArg", "lsm": "LSMArg", "struct_ops": "StructOpsArg"}[src]
		if l.calleeAttach(call.Pos(), "bpf."+fn) { // ctx.arg in a callee
			return
		}
		if l.progKind == nil || l.prog == nil || !(l.progKind.Kind == src || src == "lsm" && isLSMKind(l.progKind.Kind)) {
			l.fail(Rejected, GB027KernelTypeShape, call.Pos(), "bpf.%s may only be used in the body of a %s program", fn, src)
			return
		}
		i, targ, ok := l.ctxArgOf(call, fn)
		if !ok {
			return
		}
		if kt = l.a.kernelTypeOf(targ, call.Pos()); kt == nil {
			l.failed = true
			return
		}
		if src == "struct_ops" && !l.structOpsArgOK(call.Pos(), i, kt, nil) { // an argument in the member table
			return
		}
		if !l.declareArg(i, tpArgDecl{kt: kt, nullable: src == "tp_btf", pos: call.Pos()}) {
			return
		}
		l.emit("%s = ebpf.ctx.arg %%ctx[%d] : !ebpf.ctx<%q> -> !ebpf.kptr_or_null<%q>", src2, i, l.progKind.Kind, kt.Name)
	}
	if !l.a.checkKptrUses(s.Body, mobj, kt, src == "struct_ops") {
		l.failed = true
		return
	}
	blk := l.val()
	before := copyEnv(l.env)
	l.env = copyEnv(before)
	l.escaped = false
	l.bindKptr(mobj, blk, kt)
	presentText := l.region(func() { l.stmts(s.Body.List) })
	delete(l.kptrs, mobj)
	presentEnv, presentEsc := l.env, l.escaped
	l.env = copyEnv(before)
	l.escaped = false
	absentText := ""
	if elseBlock != nil {
		absentText = l.region(func() { l.stmts(elseBlock.List) })
	}
	absentEnv, absentEsc := l.env, l.escaped
	l.escaped = false
	if l.failed {
		return
	}
	mods := mergeVars(before, liveEnvs([]map[*types.Var]value{presentEnv, absentEnv}, []bool{presentEsc, absentEsc})...)
	absentPos := s.Body.Rbrace
	if elseBlock != nil {
		absentPos = elseBlock.Rbrace
	}
	if !presentEsc {
		l.yieldInto(&presentText, presentEnv, mods, "ebpf.yield", s.Body.Rbrace)
	}
	if !absentEsc {
		l.yieldInto(&absentText, absentEnv, mods, "ebpf.yield", absentPos)
	}
	l.env = before
	head, typeList, base := l.resultHead(mods, before)
	l.b.WriteString(fmt.Sprintf("%s%sebpf.kptr.check %s : !ebpf.kptr_or_null<%q>%s present {\n%s^present(%s: !ebpf.kptr<%q>):\n%s%s} absent {\n%s%s}%s\n",
		l.indent, head, src2, kt.Name, typeList, l.indent, blk, kt.Name, presentText, l.indent, absentText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(mods, before, base)
	}
}

// isLSMKind reports whether the kind is of the lsm family (lsm and lsm_s share the API).
func isLSMKind(kind string) bool { return kind == "lsm" || kind == "lsm_s" }

// argsSchema returns the schema args of a tp_btf / fentry program (a positional array 0..max i — unread arguments are null).
func (p *Program) argsSchema() []any {
	max := -1
	for i := range p.args {
		if i > max {
			max = i
		}
	}
	out := make([]any, max+1)
	for i := range out {
		if d, ok := p.args[i]; ok {
			out[i] = d.schemaArg()
		}
	}
	return out
}

// checkTPArgs checks that a tp_btf program reads at least one argument (unread earlier arguments are null in the schema, so a missing declaration is not an error).
func (a *analyzer) checkTPArgs(p *Program) {
	if p.ProgramType != "tp_btf" || p.body == "" /* lowering errors already reported — do not repeat */ {
		return
	}
	if len(p.args) == 0 {
		a.report(Rejected, GB027KernelTypeShape, p.decl.Name.Pos(), []string{p.Symbol}, "the tp_btf program %s reads no argument — declare at least one with bpf.TPArg[T](ctx, i) or bpf.TPArgInt[T](ctx, i) (bpf-mlir needs the types of the tracepoint arguments it reads)", p.Symbol)
	}
}

// schemaType returns the schema type of a local type field (an integer, an 8-bit integer array, a kptr).
func (f KernelField) schemaType() any {
	switch f.Kind {
	case kfArray:
		return &schemaArray{Kind: "array", Count: uint64(f.Count), Element: schemaIntOf(IntType{8, f.Signed})}
	case kfPtr:
		return map[string]string{"kind": "kptr", "struct": f.Target.Name}
	case kfStrPtr:
		return map[string]string{"kind": "strptr"} // bpf-mlir's schema strptr (schema format 15)
	case kfStruct:
		return map[string]string{"kind": "struct", "struct": f.Target.Name} // an embedded local type (a step of a field path)
	}
	return schemaIntOf(IntType{f.Bits, f.Signed})
}

// kptrChainMisuse stops `p.F.G` / `p.F[i]` (p a kernel pointer variable) — following a kernel pointer field without a check, or reading an element of an array field —
// with a kernel type message instead of a record path error ("outside the checked branch"). handled reports whether e has that shape (already reported).
func (l *lowerer) kptrChainMisuse(e ast.Expr) bool {
	root, steps := recordChain(e)
	if root == nil || len(steps) < 2 {
		return false
	}
	v, _ := l.a.info.Uses[root].(*types.Var)
	kp, isK := l.kptrs[v]
	var sels []*ast.SelectorExpr // the leading selectors (through embedded structs)
	for _, st := range steps {
		s, isSel := st.(*ast.SelectorExpr)
		if !isSel {
			break
		}
		sels = append(sels, s)
	}
	if v == nil || !isK || len(sels) == 0 {
		return false
	}
	f, i := kpathLeaf(kp.kt, sels)
	sel := sels[i]
	if f == nil {
		owner := kp.kt.goName()
		if i > 0 {
			owner = types.ExprString(sels[i-1])
		}
		l.fail(Rejected, GB027KernelTypeShape, sel.Sel.Pos(), "kernel type %s has no readable field %s", owner, sel.Sel.Name)
		return true
	}
	x := types.ExprString(sel)
	switch f.Kind {
	case kfStruct:
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the embedded kernel struct %s cannot be indexed — read its fields (%s.F)", x, x)
	case kfPtr:
		l.fail(Rejected, GB005NilCheckShape, sel.Pos(), "the kernel pointer field %s may be NULL — read it only as `if m := %s; m != nil { … m.F … }`", x, x)
	case kfArray:
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel array field %s can only be copied whole into a record field of the same type (`q.F = %s` — q a checked record pointer: ebpf.kfield.copy); its elements cannot be read", x, x)
	case kfStrPtr:
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel string field %s (bpf.KernelStr) cannot be followed or indexed — pass it only as the second argument of RingBuf.OutputKernelStr", x)
	default:
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel integer field %s is not an array or a pointer", x)
	}
	return true
}
