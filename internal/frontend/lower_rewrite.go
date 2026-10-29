package frontend

import (
	"go/ast"
	"go/constant"
	"go/types"
)

// XDP packet rewriting (bpf-mlir's packet.store and xdp.adjust_head / adjust_tail):
//
//	w.SetU8(i, v) / SetBE16 / SetBE32 / SetBE64 / SetLE16 / SetLE32 / SetLE64   → [ebpf.byteorder.to_be] → ebpf.packet.store %w[i], %v
//	st := ctx.AdjustHead(d)   → %st = ebpf.xdp.adjust_head %ctx, %d : !ebpf.ctx<"xdp"> -> i64
//	st := ctx.AdjustTail(d)   → %st = ebpf.xdp.adjust_tail %ctx, %d   (d is a constant ≤ 0 — growing the tail is not measured)
//
// **The packet generation**: lowering keeps a generation pktGen and advances it by 1 at each Adjust (packet pointers are invalid on success or failure — bpf-mlir's
// pktinval). A window keeps the generation it was made in, and a read or write stops with GB025 if it differs from the current one (on the Go line, before bpf-mlir's may-invalidate check).
// Each arm of an if / Check starts from the entry generation, and after the join the larger one wins (if any one path Adjusts, an old window is invalid after the join — the same
// conservative direction as bpf-mlir). A tail call's fallback also advances the generation (packet pointers are invalid after the attempt; gobpf windows exist only inside a Check arm, so
// no window reaches the fallback of a top-level TailCall, but the rule lives in one place).

// adjustOp returns the op if call is ctx.AdjustHead / AdjustTail.
func (l *lowerer) adjustOp(call *ast.CallExpr) string {
	if op := l.apiOp(call); op == "adjust_head" || op == "adjust_tail" {
		return op
	}
	return ""
}

// adjust lowers a ctx.AdjustHead / AdjustTail expression (the status is i64).
func (l *lowerer) adjust(call *ast.CallExpr, op string) (value, bool) {
	defer l.at(call.Pos())()
	name := map[string]string{"adjust_head": "AdjustHead", "adjust_tail": "AdjustTail"}[op]
	sel := call.Fun.(*ast.SelectorExpr)
	if l.calleeCtx { // bpf-mlir refuses an invalidating op (adjust) in a callee
		l.fail(Rejected, GB013SubprogramShape, call.Pos(), "ctx.%s changes the packet (it invalidates every window), which a subprogram that takes the context cannot do (bpf-mlir refuses it in a callee); adjust in the program and pass the status as an integer if the helper needs it", name)
		return value{}, false
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || !l.isProg || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB013SubprogramShape, call.Pos(), "ctx.%s is only available on the program's context parameter", name)
		return value{}, false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "ctx.%s cannot be inside a loop (bpf-mlir does not allow ebpf.xdp.%s in a loop body)", name, op)
		return value{}, false
	}
	i32 := vtype{bits: 32, signed: true}
	if op == "adjust_tail" {
		tv := l.a.info.Types[call.Args[0]]
		if tv.Value == nil {
			l.fail(Rejected, GB006NonConstant, call.Args[0].Pos(), "the delta of ctx.AdjustTail must be a constant ≤ 0 (only shrinking is supported)")
			return value{}, false
		}
		if d, exact := constant.Int64Val(constant.ToInt(tv.Value)); !exact || d > 0 {
			l.fail(Rejected, GB025PacketWrite, call.Args[0].Pos(), "the delta of ctx.AdjustTail must be ≤ 0 — growing the tail is not supported (the driver's tailroom is not measured), got %s", tv.Value.ExactString())
			return value{}, false
		}
	}
	d, ok := l.expr(call.Args[0], &i32)
	if !ok {
		return value{}, false
	}
	r := l.val()
	l.emit("%s = ebpf.xdp.%s %%ctx, %s : !ebpf.ctx<\"xdp\"> -> i64", r, op, d.name)
	l.pktGen++
	l.lastAdjust, l.lastAdjustName = call.Pos(), name
	return value{r, vtype{bits: 64, signed: true}}, true
}

var windowStores = map[string]struct {
	bits int
	be   bool
}{
	"SetU8": {8, false}, "SetBE16": {16, true}, "SetBE32": {32, true}, "SetBE64": {64, true},
	"SetLE16": {16, false}, "SetLE32": {32, false}, "SetLE64": {64, false},
}

// windowStore lowers statements such as `w.SetBE16(i, v)`. A receiver that is not a window or a method that is not Set gives handled = false.
func (l *lowerer) windowStore(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	spec, isSet := windowStores[sel.Sel.Name]
	recv, ok := sel.X.(*ast.Ident)
	if !isSet || !ok {
		return false
	}
	wv, _ := l.a.info.Uses[recv].(*types.Var)
	if wv == nil || !isBPFNamed(wv.Type(), "Window") {
		return false
	}
	defer l.at(call.Pos())()
	sockopt := l.progKind != nil && l.prog != nil && l.progKind.Kind == "cgroup_sockopt" // only the checked optval window of the entry program
	if sockopt && len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.%s writes the optval of a cgroup_sockopt program inside a loop — bpf-mlir allows the optval writes only outside loops; write before the loop", recv.Name, sel.Sel.Name)
		return true
	}
	if !sockopt && !l.winWritable && (l.progKind == nil || l.progKind.Kind != "xdp") { // a subprogram only when every caller is xdp (resolveWinParams)
		kind := "non-xdp"
		if l.progKind != nil {
			kind = l.progKind.Kind
		}
		l.fail(Rejected, GB025PacketWrite, call.Pos(), "%s.%s writes the packet of a %s program — packet writes are xdp-only (bpf-mlir: ebpf.packet.store)", recv.Name, sel.Sel.Name, kind)
		return true
	}
	win, ok := l.liveWindow(recv, wv)
	if !ok {
		return true
	}
	itv := l.a.info.Types[call.Args[0]]
	if itv.Value == nil {
		l.fail(Rejected, GB006NonConstant, call.Args[0].Pos(), "the index of %s.%s must be a constant", recv.Name, sel.Sel.Name)
		return true
	}
	i, exact := constant.Int64Val(constant.ToInt(itv.Value))
	width := int64(spec.bits / 8)
	if !exact || i < 0 || i > win.n-width {
		l.fail(Rejected, GB014WindowIndex, call.Args[0].Pos(), "%s.%s(%s, …) writes bytes [%s, %s+%d) outside the checked window of %d bytes%s", recv.Name, sel.Sel.Name, itv.Value.ExactString(), itv.Value.ExactString(), itv.Value.ExactString(), width, win.n, windowFix(exact, i, width))
		return true
	}
	t := vtype{bits: spec.bits}
	v, ok := l.expr(call.Args[1], &t)
	if !ok {
		return true
	}
	if spec.be && spec.bits > 8 {
		r := l.val()
		l.emit("%s = ebpf.byteorder.to_be %s : %s", r, v.name, t.mlir())
		v = value{r, t}
	}
	l.emit("ebpf.packet.store %s[%d], %s : !ebpf.pkt_window<%d>, %s", win.name, i, v.name, win.n, t.mlir())
	return true
}

// liveWindow checks that the receiver window belongs to the current packet generation (GB025 if old). Not a window, or outside the ok arm, is the same error as windowLoad.
func (l *lowerer) liveWindow(recv *ast.Ident, wv *types.Var) (window, bool) {
	win, isWin := l.windows[wv]
	if !isWin {
		l.fail(Rejected, GB005NilCheckShape, recv.Pos(), "window %s is used outside its `ok` branch", recv.Name)
		return window{}, false
	}
	if packetGenCheck && win.gen != l.pktGen {
		l.fail(Rejected, GB025PacketWrite, recv.Pos(), "window %s was checked before ctx.%s at %s — every adjust invalidates the packet's windows (on success and on failure); check the packet again with ctx.Check", recv.Name, l.lastAdjustName, posString(l.a.position(l.lastAdjust)))
		return window{}, false
	}
	return win, true
}

// armGen handles the generation for if / Check arms: each arm starts from the entry generation, and after the join the larger one wins.
func (l *lowerer) armGen(entry int, arms ...int) {
	m := entry
	for _, g := range arms {
		m = max(m, g)
	}
	l.pktGen = m
}

// sel returns the method name of call (for error messages).
func sel(call *ast.CallExpr) string {
	if s, ok := call.Fun.(*ast.SelectorExpr); ok {
		return s.Sel.Name
	}
	return "?"
}

// packetGenCheck enables the old window check (a test turns it off to confirm that bpf-mlir's may-invalidate refuses the same input — a control).
var packetGenCheck = true
