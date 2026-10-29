package frontend

import (
	"go/ast"
	"go/token"
	"go/types"
)

// iter programs (bpf-mlir v1.11.0's kind iter):
//
//	//gobpf:iter bpf_map_elem Elems
//	func dump(ctx *bpf.IterContext) {
//		if s := ctx.Seq(); s != nil { _ = s.Write(Line{Seq: ctx.SeqNum()}) }
//	}
//
//	ctx.SeqNum()   → %m = ebpf.ctx.arg %ctx[0] : !ebpf.ctx<"iter"> -> !ebpf.kptr<"bpf_iter_meta">
//	                 %n = ebpf.kfield.load %m "seq_num" : !ebpf.kptr<"bpf_iter_meta"> -> i64
//	ctx.Seq()      → %s = ebpf.kfield.ptr %m "seq" : … -> !ebpf.kptr_or_null<"seq_file"> (the if init statement — ebpf.kptr.check)
//	s.Write(rec)   → %r = ebpf.record.make …; %st = ebpf.seq.write %s, %r : !ebpf.kptr<"seq_file">, !ebpf.record<…> -> i64
//
// bpf_iter_meta and seq_file are local types in the schema's core.kernel_types (CO-RE — the same fields as bpf-mlir's iter schema). The only target is bpf_map_elem,
// and the directive's second word is the map to iterate (bpf.Array / bpf.Hash — the kernel's bpf_iter_attach_map type set). No result (done).

// iterTargets holds the iter targets gobpf accepts (the range bpf-mlir measured).
var iterTargets = map[string]bool{"bpf_map_elem": true}

// iterDirective checks `//gobpf:iter <target> <map>` and returns the target (the map name goes to a.iterMapOf).
func (a *analyzer) iterDirective(fd *ast.FuncDecl, at token.Pos, fields []string) (string, int, bool) {
	if len(fields) != 2 || !iterTargets[fields[0]] || !cIdent.MatchString(fields[1]) {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:iter takes the iterator target and the map to iterate (`//gobpf:iter bpf_map_elem <map variable>` — bpf_map_elem is the only target go supports), got %v", fields)
		return "", 0, false
	}
	for _, m := range a.maps {
		if m.Symbol != fields[1] {
			continue
		}
		switch m.Kind {
		case "array", "hash", "lru_hash", "percpu_array", "percpu_hash", "lru_percpu_hash":
			a.iterMapOf[fd] = fields[1]
			return fields[0], 0, true
		}
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:iter %s %s: %s is a %s map — a bpf_map_elem iterator iterates an array or a hash map (the kernel's bpf_iter_attach_map)", fields[0], fields[1], fields[1], m.Kind)
		return "", 0, false
	}
	a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:iter %s %s: no map variable named %s in this package", fields[0], fields[1], fields[1])
	return "", 0, false
}

// iterKernelTypes holds the local types bpf_iter_meta and seq_file (added to the schema's kernel_types on first use).
func (a *analyzer) iterKernelTypes() (meta, seq *KernelType) {
	for _, kt := range a.kernelOrder {
		if kt.Name == "bpf_iter_meta" {
			meta = kt
		}
		if kt.Name == "seq_file" {
			seq = kt
		}
	}
	if meta != nil && seq != nil {
		return meta, seq
	}
	seq = &KernelType{Name: "seq_file", Fields: []KernelField{{Name: "size", GoName: "size", Kind: kfInt, Bits: 64}}}
	meta = &KernelType{Name: "bpf_iter_meta", Fields: []KernelField{
		{Name: "seq", GoName: "seq", Kind: kfPtr, Target: seq},
		{Name: "seq_num", GoName: "seq_num", Kind: kfInt, Bits: 64},
	}}
	a.kernelOrder = append(a.kernelOrder, meta, seq)
	return meta, seq
}

// goName is the Go name of a local type (iter's bpf_iter_meta / seq_file have no Go declaration — the kernel struct name).
func (kt *KernelType) goName() string {
	if kt.GoType == nil {
		return kt.Name
	}
	return kt.GoType.Obj().Name()
}

// iterPlace checks that ctx.SeqNum / ctx.Seq is called on the program context in the body of an iter program (outside loops).
func (l *lowerer) iterPlace(e *ast.CallExpr) bool {
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	name := sel.Sel.Name
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "iter" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s may only be called in the body of an iter program (func f(ctx *bpf.IterContext) with //gobpf:iter bpf_map_elem <map>)", name)
		return false
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s must be called on the program's context parameter", name)
		return false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "ctx.%s cannot be called inside a loop (bpf-mlir does not allow ctx.arg / kfield of kernel pointers in a loop body) — call it before the loop", name)
		return false
	}
	return true
}

// iterMeta emits the kernel pointer to bpf_iter_meta (ctx.arg index 0) and returns its name.
func (l *lowerer) iterMeta() (string, *KernelType, *KernelType) {
	meta, seq := l.a.iterKernelTypes()
	m := l.val()
	l.emit("%s = ebpf.ctx.arg %%ctx[0] : !ebpf.ctx<\"iter\"> -> !ebpf.kptr<\"bpf_iter_meta\">", m)
	return m, meta, seq
}

// iterSeqNum turns `ctx.SeqNum()` into kfield.load. handled reports whether e is that call.
func (l *lowerer) iterSeqNum(e *ast.CallExpr) (value, bool, bool) {
	switch l.callOp(e) {
	case "iter_seq_num":
	case "iter_seq":
		l.fail(Rejected, GB005NilCheckShape, e.Pos(), "ctx.Seq() may be NULL — the supported form is `if s := ctx.Seq(); s != nil { … }`")
		return value{}, false, true
	default:
		return value{}, false, false
	}
	if !l.iterPlace(e) {
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	m, _, _ := l.iterMeta()
	r := l.val()
	l.emit("%s = ebpf.kfield.load %s \"seq_num\" : !ebpf.kptr<\"bpf_iter_meta\"> -> i64", r, m)
	return value{r, vtype{bits: 64}}, true, true
}

// seqWrite turns `s.Write(rec)` (s is the checked seq_file pointer from ctx.Seq()) into record.make and seq.write. handled reports whether e is that call.
func (l *lowerer) seqWrite(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "seq_write" {
		return value{}, false, false
	}
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	id, _ := ast.Unparen(sel.X).(*ast.Ident)
	var kp kptrVal
	ok := false
	if id != nil {
		if v, isVar := l.a.info.Uses[id].(*types.Var); isVar && v != nil {
			kp, ok = l.kptrs[v]
		}
	}
	if !ok || kp.kt.Name != "seq_file" {
		l.fail(Rejected, GB005NilCheckShape, e.Pos(), "SeqFile.Write needs the checked pointer of `if s := ctx.Seq(); s != nil { … }`")
		return value{}, false, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "SeqFile.Write cannot be called inside a loop — write before the loop")
		return value{}, false, true
	}
	arg := e.Args[0]
	if _, isNamed := l.a.info.Types[arg].Type.(*types.Named); !isNamed {
		l.fail(Rejected, GB008ProgramShape, arg.Pos(), "SeqFile.Write takes a record value (a composite literal of a named struct type of this package), not %s", l.a.info.Types[arg].Type)
		return value{}, false, true
	}
	rec, recOK := l.a.recordOf(l.a.info.Types[arg].Type, arg.Pos(), "SeqFile.Write")
	if !recOK {
		l.failed = true
		return value{}, false, true
	}
	rv, mk := l.recordMake(arg, rec)
	if !mk {
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.seq.write %s, %s : !ebpf.kptr<\"seq_file\">, %s -> i64", r, kp.name, rv, rec.mlir())
	return value{r, vtype{bits: 64, signed: true}}, true, true
}
