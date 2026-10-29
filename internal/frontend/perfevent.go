package frontend

import "go/ast"

// perf_event programs (bpf-mlir's perf_event kind):
//
//	func onSample(ctx *bpf.PerfEventContext) {
//		p := ctx.SamplePeriod()   → %v = ebpf.ctx.field %ctx "sample_period" : !ebpf.ctx<"perf_event"> -> i64
//	}
//
// The declaration is `ebpf.program @f "perf_event" arch "x86_64"` (the schema's arch — offset 168 of bpf_perf_event_data depends on the size of x86_64's pt_regs).
// A read inside a loop is GB018: the constraints of bpf-mlir's ctx.field op (EBPF_CtxFieldOp in EBPFOps.td) have no loop rule, but the list of ops that the ebpf.loop verifier
// allows in a body (allowedInLoop in lib/Dialect/EBPF/IR/EBPFDialect.cpp — "is not allowed inside ebpf.loop (…)") does not include ctx.field
// (checked when perf_event support was added). Subprograms do not take a perf_event context (not in calleeCtxKinds).

// samplePeriod lowers `ctx.SamplePeriod()` to ebpf.ctx.field. handled reports whether e is that call.
func (l *lowerer) samplePeriod(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "perf_sample_period" {
		return value{}, false, false
	}
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "perf_event" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.SamplePeriod may only be called in the body of a perf_event program (func f(ctx *bpf.PerfEventContext))")
		return value{}, false, true
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.SamplePeriod must be called on the program's context parameter")
		return value{}, false, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "ctx.SamplePeriod cannot be read inside a loop (bpf-mlir does not allow ebpf.ctx.field in a loop body) — read it before the loop")
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.ctx.field %%ctx %q : !ebpf.ctx<%q> -> i64", r, "sample_period", "perf_event")
	return value{r, vtype{bits: 64}}, true, true
}
