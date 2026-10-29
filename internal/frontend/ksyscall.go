package frontend

import (
	"go/ast"
	"go/token"
	"go/types"
)

// ksyscall (bpf-mlir v1.11.0's feature paths F65 / F67):
//
//	//gobpf:ksyscall prctl
//	func f(ctx *bpf.KsyscallContext) {
//		x := bpf.KsyscallArg[uint64](ctx, 4)   → %v = ebpf.ksyscall.arg %ctx 4 : !ebpf.ctx<"ksyscall"> -> i64
//	}
//
// The declaration is `ebpf.program @f "ksyscall" attach "prctl" arch "x86_64"`, and the schema params map n to a type (the same shape as kprobe — the requirements' sysarg
// is checked against the tracefs format). KsyscallArg only as a top-level statement of the body (bpf-mlir refuses the ctx in loops and static funcs — the first version stays near the entry).

// ksyscallArgAssign lowers the body's top-level `x := bpf.KsyscallArg[T](ctx, n)`. handled reports whether the right-hand side of s is KsyscallArg.
func (l *lowerer) ksyscallArgAssign(s *ast.AssignStmt) bool {
	if len(s.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
	if !ok || l.callOp(call) != "ksyscall_arg" {
		return false
	}
	const fn = "bpf.KsyscallArg"
	defer l.at(call.Pos())()
	if l.calleeAttach(call.Pos(), fn) { // a subprogram that takes the context
		return true
	}
	if l.progKind == nil || l.progKind.Kind != "ksyscall" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be used in the body of a ksyscall program (func f(ctx *bpf.KsyscallContext) with //gobpf:ksyscall <syscall>)", fn)
		return true
	}
	top := false
	for _, st := range l.fnBody.List {
		if st == ast.Stmt(s) {
			top = true
		}
	}
	id, _ := s.Lhs[0].(*ast.Ident)
	if !top || len(s.Lhs) != 1 || id == nil || s.Tok != token.DEFINE || id.Name == "_" {
		l.fail(Rejected, GB008ProgramShape, s.Pos(), "%s must be a top-level statement of the ksyscall program body, `x := %s[T](ctx, n)`", fn, fn)
		return true
	}
	if cid, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[cid] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return true
	}
	n, ok := l.argNumber(call.Args[1], fn)
	if !ok {
		return true
	}
	it, isInt := intTypeOf(l.a.info.Types[call].Type)
	if !isInt {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s reads an 8 / 16 / 32 / 64-bit integer", fn)
		return true
	}
	p := l.prog
	if p.Params == nil {
		p.Params, p.paramPos = map[int]IntType{}, map[int]token.Pos{}
	}
	if prev, seen := p.Params[n]; seen && prev != it {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the ksyscall program %s is read as %s here but as %s at %s — one argument has one type (schema params)", n, p.Symbol, goIntName(it), goIntName(prev), posString(l.a.position(p.paramPos[n])))
		return true
	} else if !seen {
		p.Params[n], p.paramPos[n] = it, call.Pos()
	}
	v, _ := l.a.info.Defs[id].(*types.Var)
	if v == nil {
		l.fail(Rejected, GB008ProgramShape, id.Pos(), "`%s := %s…` must declare a new variable", id.Name, fn)
		return true
	}
	r := l.val()
	l.emit("%s = ebpf.ksyscall.arg %%ctx %d : !ebpf.ctx<\"ksyscall\"> -> %s", r, n, it.mlir())
	l.env[v] = value{r, vtypeOf(it)}
	return true
}
