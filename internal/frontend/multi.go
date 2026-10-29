package frontend

import "go/ast"

// Multi probes (bpf-mlir's kprobe_multi / uprobe_multi kinds):
//
//	//gobpf:kprobe_multi bpf_fentry_test1 bpf_fentry_test2
//	func f(ctx *bpf.KprobeContext) {
//		i := bpf.ProbeTargetIndex(ctx)   → %v = ebpf.probe.target_index %ctx : !ebpf.ctx<"kprobe_multi"> -> i64
//		a := bpf.KprobeArg[int32](ctx, 1) → ebpf.kprobe.arg %ctx 1 : !ebpf.ctx<"kprobe_multi"> -> i32
//	}
//
// The declaration is `ebpf.program @f "kprobe_multi" attach ["bpf_fentry_test1", "bpf_fentry_test2"] arch "x86_64"`; the schema's attach_target is an array of names.

// probeTargetIndex lowers `bpf.ProbeTargetIndex(ctx)` to ebpf.probe.target_index. handled reports whether e is that call.
func (l *lowerer) probeTargetIndex(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "probe_target_index" {
		return value{}, false, false
	}
	if l.progKind == nil || l.prog == nil || !hasTargetIndex(l.progKind.Kind) { // for usdt, the index of the probe point
		kind := "a subprogram"
		if l.progKind != nil {
			kind = "a " + l.progKind.Kind + " program"
		}
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "bpf.ProbeTargetIndex may only be called in the body of a multi probe program (//gobpf:kprobe_multi f1 f2 …, kretprobe_multi, uprobe_multi, uretprobe_multi) or a usdt program — not in %s", kind)
		return value{}, false, true
	}
	if id, ok := ast.Unparen(e.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Args[0].Pos(), "the argument of bpf.ProbeTargetIndex must be the program's context parameter")
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.probe.target_index %%ctx : !ebpf.ctx<%q> -> i64", r, l.progKind.Kind)
	return value{r, vtype{bits: 64}}, true, true
}
