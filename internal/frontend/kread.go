package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// Reads behind a kprobe pointer argument (bpf-mlir v1.11.0's ebpf.kernel.read_scalar):
//
//	flags, st := bpf.KprobeRead[uint64](ctx, 3, 0)
//	  → %a = ebpf.kprobe.arg %ctx 3 : !ebpf.ctx<"kprobe"> -> i64                    (a direct producer — in place at each call)
//	    %r:2 = ebpf.kernel.read_scalar %a offset 0 : i64 -> i64, i64              (the value and raw status — 0 on failure)
//
// Only as a top-level statement `v, st := …` of the program body (inside if / loop / subprogram it stops — widened on demand). n is a ptr in the schema params
// (the same declaration as PtrParams).

// kreadMaxOffset is the read_scalar offset limit (bpf-mlir's op verifier — 0..4095).
const kreadMaxOffset = 4095

// kprobeReadAssign lowers `v, st := bpf.KprobeRead[T](ctx, n, off)`. handled reports whether the right-hand side of s is KprobeRead.
func (l *lowerer) kprobeReadAssign(s *ast.AssignStmt) bool {
	if len(s.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
	if !ok || l.callOp(call) != "kprobe_read" {
		return false
	}
	const fn = "bpf.KprobeRead"
	defer l.at(call.Pos())()
	if l.calleeAttach(call.Pos(), fn) { // a subprogram that takes the context
		return true
	}
	if l.progKind == nil || l.progKind.Kind != "kprobe" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be used in the body of a kprobe program (func f(ctx *bpf.KprobeContext) with //gobpf:kprobe) — bpf-mlir reads through a pointer argument of an ordinary x86_64 kprobe only", fn)
		return true
	}
	top := false
	for _, st := range l.fnBody.List {
		if st == ast.Stmt(s) {
			top = true
		}
	}
	if !top || len(s.Lhs) != 2 {
		l.fail(Rejected, GB008ProgramShape, s.Pos(), "%s must be a top-level statement of the kprobe program body, `v, st := %s[T](ctx, n, off)` (not inside if / for — the first version keeps the read next to the program entry)", fn, fn)
		return true
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return true
	}
	n, ok := l.argNumber(call.Args[1], fn)
	if !ok {
		return true
	}
	otv := l.a.info.Types[call.Args[2]]
	off, exact := int64(-1), false
	if otv.Value != nil {
		off, exact = constant.Int64Val(constant.ToInt(otv.Value))
	}
	if otv.Value == nil || !exact || off < 0 || off > kreadMaxOffset {
		l.fail(Rejected, GB008ProgramShape, call.Args[2].Pos(), "the offset of %s must be a constant 0..%d (bytes from the pointer — bpf-mlir's kernel.read_scalar)", fn, kreadMaxOffset)
		return true
	}
	tup, _ := l.a.info.Types[call].Type.(*types.Tuple)
	if tup == nil || tup.Len() != 2 {
		l.failed = true // Go's type check stops it
		return true
	}
	it, isInt := intTypeOf(tup.At(0).Type())
	if !isInt {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s reads an 8 / 16 / 32 / 64-bit integer, got %s", fn, l.a.typeString(tup.At(0).Type()))
		return true
	}
	p := l.prog
	if prev, seen := p.Params[n]; seen {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the kprobe program %s is read through as a pointer here but as %s at %s — one argument has one type (schema params)", n, p.Symbol, goIntName(prev), posString(l.a.position(p.paramPos[n])))
		return true
	}
	if p.PtrParams == nil {
		p.PtrParams = map[int]token.Pos{}
	}
	if _, seen := p.PtrParams[n]; !seen {
		p.PtrParams[n] = call.Pos()
	}
	a := l.val()
	l.emit("%s = ebpf.kprobe.arg %%ctx %d : !ebpf.ctx<\"kprobe\"> -> i64", a, n)
	t := vtypeOf(it)
	r := l.val()
	l.emit("%s:2 = ebpf.kernel.read_scalar %s offset %d : i64 -> %s, i64", r, a, off, t.mlir())
	results := []value{{r + "#0", t}, {r + "#1", vtype{bits: 64, signed: true}}}
	for i, lhs := range s.Lhs {
		id, _ := lhs.(*ast.Ident)
		if id == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, lhs.Pos(), "assignment target must be a local variable")
			return true
		}
		if id.Name == "_" {
			continue
		}
		v := l.localVar(id, s.Tok == token.DEFINE)
		if v == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "assignment target %s must be a local variable", id.Name)
			return true
		}
		l.setVar(id, v, results[i])
	}
	return true
}

// kprobeReadDiscarded stops KprobeRead used as an expression statement or in a single-value context (it would silently discard the status — GB017). handled reports whether call is KprobeRead.
func (l *lowerer) kprobeReadDiscarded(call *ast.CallExpr) bool {
	if l.callOp(call) != "kprobe_read" {
		return false
	}
	l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the value and the raw status of bpf.KprobeRead are discarded — use them (`v, st := bpf.KprobeRead[T](ctx, n, off)`) or discard the status explicitly (`v, _ := …` — a failed read gives 0, the same as a read of 0)")
	return true
}
