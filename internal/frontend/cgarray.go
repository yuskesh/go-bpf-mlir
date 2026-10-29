package frontend

import "go/ast"

// cgroup_array (bpf-mlir v1.11.0's ebpf.task.under_cgroup / ebpf.skb.under_cgroup):
//
//	st := CG.TaskUnder(k)       → %st = ebpf.task.under_cgroup %m[%k] : !ebpf.map<"cgroup_array", i32, i32>, i32 -> i64
//	st := CG.SkbUnder(ctx, k)   → %st = ebpf.skb.under_cgroup %ctx, %m[%k] : !ebpf.ctx<"sched_cls">, !ebpf.map<"cgroup_array", i32, i32>, i32 -> i64
//
// The raw status (1 / 0 / negative errno). Which kinds may call TaskUnder is decided by the requirements and the verifier at load time (6.x: tracing kinds only
// — a bpf-mlir research finding); SkbUnder only on the sched_cls program body's context (a callee's ctx is refused — a bpf-mlir constraint). The index is a u32 value (need not be constant).

// cgarrUnder lowers TaskUnder / SkbUnder.
func (l *lowerer) cgarrUnder(call *ast.CallExpr, m *BpfMap, op string) (value, bool) {
	defer l.at(call.Pos())()
	kt := vtypeOf(*m.Key.Int)
	if op == "cgarr_task" {
		k, ok := l.expr(call.Args[0], &kt)
		if !ok {
			return value{}, false
		}
		r := l.val()
		l.emit("%s = ebpf.task.under_cgroup %s[%s] : %s, %s -> i64", r, l.mapArgs[m], k.name, l.mapType(m), kt.mlir())
		return value{r, vtype{bits: 64, signed: true}}, true
	}
	if l.progKind == nil || l.progKind.Kind != "sched_cls" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.SkbUnder asks about the skb's socket — it may only be called in the body of a tc program (func f(ctx *bpf.TCIngressContext / *bpf.TCEgressContext) bpf.TCAction)", m.Symbol)
		return value{}, false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s.SkbUnder must be the program's context parameter", m.Symbol)
		return value{}, false
	}
	k, ok := l.expr(call.Args[1], &kt)
	if !ok {
		return value{}, false
	}
	r := l.val()
	l.emit("%s = ebpf.skb.under_cgroup %%ctx, %s[%s] : !ebpf.ctx<\"sched_cls\">, %s, %s -> i64", r, l.mapArgs[m], k.name, l.mapType(m), kt.mlir())
	return value{r, vtype{bits: 64, signed: true}}, true
}
