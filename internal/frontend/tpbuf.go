package frontend

import "go/ast"

// The writable buffer of raw_tp_writable (bpf-mlir's ebpf.tp.buffer.load / store):
//
//	x := ctx.Buffer()   → %x = ebpf.tp.buffer.load %ctx[0] : !ebpf.ctx<"raw_tp_writable"> -> i32
//	ctx.SetBuffer(v)    → ebpf.tp.buffer.store %ctx[0], %v : !ebpf.ctx<"raw_tp_writable">, i32
//
// bpf-mlir's ops accept only the program's own entry ctx, offset 0 and i32 — the frontend accepts only calls on the context
// parameter of the program body (not a subprogram), and stops inside a loop (outside bpf-mlir's evidence — GB018).

// tpBufCheck checks the place of a Buffer / SetBuffer call (it reports the error and returns false).
func (l *lowerer) tpBufCheck(e *ast.CallExpr, name string) bool {
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "raw_tp_writable" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s may only be called in the body of a raw_tp_writable program (func f(ctx *bpf.RawTPWritableContext) with //gobpf:raw_tp_writable <tracepoint>) — a subprogram cannot take the context", name)
		return false
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s must be called on the program's context parameter", name)
		return false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "ctx.%s cannot be called inside a loop (the writable buffer access is verified outside loops only) — read or write it before the loop", name)
		return false
	}
	return true
}

// tpBufLoad lowers `ctx.Buffer()` to ebpf.tp.buffer.load. handled reports whether e is that call.
func (l *lowerer) tpBufLoad(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "tpbuf_load" {
		return value{}, false, false
	}
	if !l.tpBufCheck(e, "Buffer") {
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.tp.buffer.load %%ctx[0] : !ebpf.ctx<\"raw_tp_writable\"> -> i32", r)
	return value{r, vtype{bits: 32, signed: true}}, true, true
}

// tpBufStore lowers the statement `ctx.SetBuffer(v)` to ebpf.tp.buffer.store (false for any other statement).
func (l *lowerer) tpBufStore(e *ast.CallExpr) bool {
	if l.callOp(e) != "tpbuf_store" {
		return false
	}
	if !l.tpBufCheck(e, "SetBuffer") {
		return true
	}
	want := vtype{bits: 32, signed: true}
	v, ok := l.expr(e.Args[0], &want)
	if !ok {
		return true
	}
	defer l.at(e.Pos())()
	l.emit("ebpf.tp.buffer.store %%ctx[0], %s : !ebpf.ctx<\"raw_tp_writable\">, i32", v.name)
	return true
}
