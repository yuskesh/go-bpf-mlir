package frontend

import "go/ast"

// fsession programs (bpf-mlir v1.11.0's kind fsession — loading needs a cilium/ebpf with fsession support):
//
//	//gobpf:fsession bpf_fentry_test1
//	func onSess(ctx *bpf.FsessionContext) {
//		if ctx.IsReturn() { … ctx.Cookie() … } else { ctx.SetCookie(v) }
//	}
//
//	ctx.IsReturn()    → %r = ebpf.session.is_return %ctx : !ebpf.ctx<"fsession"> -> i1
//	ctx.Cookie()      → %c = ebpf.session.cookie.load %ctx : !ebpf.ctx<"fsession"> -> i64
//	ctx.SetCookie(v)  → ebpf.session.cookie.store %ctx, %v : !ebpf.ctx<"fsession">, i64
//
// The same program runs at the function's entry and return (kfuncs bpf_session_is_return / bpf_session_cookie — signatures differ by kernel version; fsession is 7.1.8 only).
// Arguments cannot be read (bpf-mlir's fsession has SIG None), and there is no result (done). Inside a loop it is GB018 (session ops are not among the ops bpf-mlir's ebpf.loop body allows),
// and subprograms do not take the fsession context.

// sessionOp returns the api-table op name if e is a call of a session method (IsReturn / Cookie / SetCookie).
func (l *lowerer) sessionOp(e *ast.CallExpr) string {
	switch op := l.callOp(e); op {
	case "session_is_return", "session_cookie", "session_set_cookie":
		return op
	}
	return ""
}

// sessionPlace checks that a session method is called on the program context at the top level (outside loops) of an fsession program body.
func (l *lowerer) sessionPlace(e *ast.CallExpr) bool {
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	name := sel.Sel.Name
	if l.progKind == nil || l.prog == nil || (l.progKind.Kind != "fsession" && l.progKind.Kind != "kprobe_session") { // kprobe_session uses the same session ops
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s may only be called in the body of a fsession program (func f(ctx *bpf.FsessionContext) with //gobpf:fsession <function>) or a kprobe_session program (func f(ctx *bpf.KprobeSessionContext) bpf.KprobeSessionRet with //gobpf:kprobe_session <function>)", name)
		return false
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s must be called on the program's context parameter", name)
		return false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "ctx.%s cannot be called inside a loop (bpf-mlir does not allow the session ops in a loop body) — call it before the loop", name)
		return false
	}
	return true
}

// sessionRead turns `ctx.IsReturn()` / `ctx.Cookie()` into session ops. handled reports whether e is that call.
func (l *lowerer) sessionRead(e *ast.CallExpr) (value, bool, bool) {
	op := l.sessionOp(e)
	if op == "" {
		return value{}, false, false
	}
	if op == "session_set_cookie" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.SetCookie has no value — call it as a statement")
		return value{}, false, true
	}
	if !l.sessionPlace(e) {
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	if op == "session_is_return" {
		l.emit("%s = ebpf.session.is_return %%ctx : !ebpf.ctx<%q> -> i1", r, l.progKind.Kind)
		return value{r, vtype{isBool: true}}, true, true
	}
	l.emit("%s = ebpf.session.cookie.load %%ctx : !ebpf.ctx<%q> -> i64", r, l.progKind.Kind)
	return value{r, vtype{bits: 64}}, true, true
}

// sessionWrite turns the statement `ctx.SetCookie(v)` into ebpf.session.cookie.store (false for other statements).
func (l *lowerer) sessionWrite(call *ast.CallExpr) bool {
	op := l.sessionOp(call)
	if op == "" {
		return false
	}
	if op != "session_set_cookie" {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "the value of ctx.%s is discarded — use it", sel(call))
		return true
	}
	if !l.sessionPlace(call) {
		return true
	}
	defer l.at(call.Pos())()
	t := vtype{bits: 64}
	v, ok := l.expr(call.Args[0], &t)
	if !ok {
		return true
	}
	l.emit("ebpf.session.cookie.store %%ctx, %s : !ebpf.ctx<%q>, i64", v.name, l.progKind.Kind)
	return true
}
