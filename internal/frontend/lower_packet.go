package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// Packet reads: `if w, ok := ctx.Check(off, n); ok { … } [else { … }]` → the in_range / out_of_range of ebpf.packet.check
// (with the arms joined), window reads `w.U8(i)` / `w.BE16(i)` … → ebpf.packet.window_load (+ ebpf.byteorder.from_be for BE).
// ebpf.packet.load, which returns 0 when out of range, is never emitted.

type window struct {
	name string // the block argument of in_range
	n    int64  // the number of checked bytes
	gen  int    // the packet generation when made (stops a use after Adjust)
}

// isCheckIf reports whether s has the shape `if w, ok := ctx.Check(…); …` (init defines the result of a ctx.Check call).
func (l *lowerer) isCheckIf(s *ast.IfStmt) bool {
	as, ok := s.Init.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	return ok && l.apiOp(call) == "packet_check"
}

// apiOp returns the op if call is a call of a bpf method in the table.
func (l *lowerer) apiOp(call *ast.CallExpr) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	obj := l.a.info.Uses[sel.Sel]
	if obj == nil || !inAPIPackage(obj) {
		return ""
	}
	e, ok := lookupAPI(obj)
	if !ok {
		return ""
	}
	return e.op
}

func (l *lowerer) checkIf(s *ast.IfStmt) {
	shape := func(p token.Pos, what string) {
		l.fail(Rejected, GB005NilCheckShape, p, "%s — the supported form is `if w, ok := ctx.Check(off, n); ok { … } [else { … }]`", what)
	}
	if (!l.isProg && !l.calleeCtx) || l.ctxVar == nil { // also Check inside a subprogram that takes the context
		l.fail(Rejected, GB013SubprogramShape, s.Pos(), "ctx.Check is only available in the program itself or in a subprogram that takes the context as its first parameter (func f(ctx *bpf.XDPContext, …))")
		return
	}
	as := s.Init.(*ast.AssignStmt)
	call := as.Rhs[0].(*ast.CallExpr)
	for _, lc := range l.loops {
		if lc.backedge { // bpf-mlir's packet.check only in a (U) body
			l.fail(Rejected, GB018LoopShape, call.Pos(), "ctx.Check cannot be inside a `//gobpf:loop backedge` loop (bpf-mlir allows packet checks only in unrolled loop bodies) — drop the directive (unroll) or check before the loop")
			return
		}
	}
	sel := call.Fun.(*ast.SelectorExpr)
	if recv, ok := sel.X.(*ast.Ident); !ok || l.a.info.Uses[recv] != l.ctxVar {
		shape(sel.X.Pos(), "Check must be called on the program's context parameter")
		return
	}
	if as.Tok != token.DEFINE || len(as.Lhs) != 2 {
		shape(as.Pos(), "the if statement's init must be `w, ok := ctx.Check(off, n)`")
		return
	}
	wid, _ := as.Lhs[0].(*ast.Ident)
	okid, _ := as.Lhs[1].(*ast.Ident)
	if wid == nil || okid == nil || wid.Name == "_" || okid.Name == "_" {
		shape(as.Pos(), "both the window and ok must be named")
		return
	}
	wobj, _ := l.a.info.Defs[wid].(*types.Var)
	okobj, _ := l.a.info.Defs[okid].(*types.Var)
	if c, isID := s.Cond.(*ast.Ident); !isID || l.a.info.Uses[c] != okobj {
		shape(s.Cond.Pos(), fmt.Sprintf("the condition must be exactly `%s`", okid.Name))
		return
	}
	// n is a positive constant (1..65535 — the len range of bpf-mlir's packet.check).
	ntv := l.a.info.Types[call.Args[1]]
	if ntv.Value == nil {
		l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the length of ctx.Check must be a constant")
		return
	}
	n, exact := constant.Int64Val(constant.ToInt(ntv.Value))
	if !exact || n < 1 || n > 65535 {
		l.fail(Rejected, GB014WindowIndex, call.Args[1].Pos(), "the length of ctx.Check must be in [1, 65535], got %s", ntv.Value.ExactString())
		return
	}
	var elseBlock *ast.BlockStmt
	if s.Else != nil {
		eb, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			shape(s.Else.Pos(), "else-if is not supported after ctx.Check")
			return
		}
		elseBlock = eb
		l.rejectWindowUses(eb, wobj, "the packet is shorter than the checked range in the else branch")
		l.rejectWindowUses(eb, okobj, "ok is only the condition")
		if l.failed {
			return
		}
	}
	l.rejectWindowUses(s.Body, okobj, "ok is only the condition")
	if l.failed {
		return
	}
	offT := vtype{bits: 32}
	off, ok := l.expr(call.Args[0], &offT)
	if !ok {
		return
	}
	// A break / continue at the end of a Check arm inside a loop: break / continue cannot cross the packet.check region (the parent is ebpf.if /
	// ref.check), so an i8 exit mark (0 = fall through, 1 = break, 2 = continue) is added to the arm results and yielded, and an ebpf.if after the region does the break / continue
	// (bpf-mlir's recommended shape — a generalization of packet.check's i1 → ebpf.if → break). A Check without a mark generates the same output as before.
	inList, inCode := l.checkArmExit(s.Body.List)
	var outList []ast.Stmt
	outCode := int64(0)
	if elseBlock != nil {
		outList, outCode = l.checkArmExit(elseBlock.List)
	}
	var exitVar *types.Var
	if inCode != 0 || outCode != 0 {
		exitVar = types.NewVar(token.NoPos, nil, "gobpf_exit", types.Typ[types.Uint8])
		l.env[exitVar] = l.constant(constant.MakeInt64(0), vtype{bits: 8})
	}
	arm := func(list []ast.Stmt, code int64) {
		l.checkArmDepth++
		l.stmts(list)
		l.checkArmDepth--
		if code != 0 && !l.failed {
			l.env[exitVar] = l.constant(constant.MakeInt64(code), vtype{bits: 8})
		}
	}
	w := l.val()
	before := copyEnv(l.env)
	l.env = copyEnv(before)
	if l.windows == nil {
		l.windows = map[*types.Var]window{}
	}
	gen0 := l.pktGen // each arm starts from the entry packet generation
	l.windows[wobj] = window{name: w, n: n, gen: l.pktGen}
	inText := l.region(func() { arm(inList, inCode) })
	delete(l.windows, wobj)
	inEnv := l.env
	l.env = copyEnv(before)
	genIn := l.pktGen
	l.pktGen = gen0
	outText := ""
	if elseBlock != nil {
		outText = l.region(func() { arm(outList, outCode) })
	}
	outEnv := l.env
	l.armGen(gen0, genIn, l.pktGen)
	if l.failed {
		return
	}
	mods := mergeVars(before, inEnv, outEnv)
	outPos := s.Body.Rbrace
	if elseBlock != nil {
		outPos = elseBlock.Rbrace
	}
	l.yieldInto(&inText, inEnv, mods, "ebpf.yield", s.Body.Rbrace)
	l.yieldInto(&outText, outEnv, mods, "ebpf.yield", outPos)
	l.env = before
	head, typeList, base := l.resultHead(mods, before)
	l.b.WriteString(fmt.Sprintf("%s%sebpf.packet.check %%ctx[%s] len %d : !ebpf.ctx<%q>, i32%s in_range {\n%s^in(%s: !ebpf.pkt_window<%d>):\n%s%s} out_of_range {\n%s%s}%s\n",
		l.indent, head, off.name, n, l.progKind.Kind, typeList, l.indent, w, n, inText, l.indent, outText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(mods, before, base)
	}
	if exitVar != nil {
		l.exitBranches(exitVar, inCode, outCode, s)
	}
}

// checkArmExit returns the statements without it and the exit mark (1 = break, 2 = continue) if the last statement of a Check arm inside a loop is break / continue.
func (l *lowerer) checkArmExit(list []ast.Stmt) ([]ast.Stmt, int64) {
	if len(l.loops) == 0 || len(list) == 0 {
		return list, 0
	}
	br, ok := list[len(list)-1].(*ast.BranchStmt)
	if !ok || br.Label != nil || (br.Tok != token.BREAK && br.Tok != token.CONTINUE) {
		return list, 0
	}
	if br.Tok == token.CONTINUE {
		return list[:len(list)-1], 2
	}
	return list[:len(list)-1], 1
}

// exitBranches does break / continue by the exit mark after packet.check (the values are all loop-carried values after the join). No path discards the mark —
// it emits one ebpf.if per mark the arms use (a test checks this in the generated files).
func (l *lowerer) exitBranches(exitVar *types.Var, inCode, outCode int64, s *ast.IfStmt) {
	defer l.at(s.Pos())()
	code := l.env[exitVar]
	delete(l.env, exitVar)
	carried := l.loops[len(l.loops)-1].carried
	for _, c := range []struct {
		code int64
		op   string
	}{{1, "ebpf.break"}, {2, "ebpf.continue"}} {
		if inCode != c.code && outCode != c.code {
			continue
		}
		k := l.constant(constant.MakeInt64(c.code), vtype{bits: 8})
		cond := l.val()
		l.emit("%s = arith.cmpi eq, %s, %s : i8", cond, code.name, k.name)
		thenT := l.region(func() { l.emit("%s", l.branchText(c.op, carried)) })
		elseT := l.region(func() { l.emit("ebpf.if.yield") })
		l.b.WriteString(fmt.Sprintf("%sebpf.if %s {\n%s%s} else {\n%s%s}%s\n", l.indent, cond, thenT, l.indent, elseT, l.indent, l.locSuffix(s.Pos())))
	}
}

func (l *lowerer) rejectWindowUses(n ast.Node, v *types.Var, why string) {
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && l.a.info.Uses[id] == v {
			l.fail(Rejected, GB005NilCheckShape, id.Pos(), "use of %s here is not allowed: %s", id.Name, why)
		}
		return true
	})
}

var windowLoads = map[string]struct {
	bits int
	be   bool
}{
	"U8": {8, false}, "BE16": {16, true}, "BE32": {32, true}, "BE64": {64, true},
	"LE16": {16, false}, "LE32": {32, false}, "LE64": {64, false},
}

// windowFix returns how to fix an index outside the window (found in the tutorial: the message did not say how to fix it). It says nothing for a negative index or a non-constant value.
func windowFix(exact bool, i, width int64) string {
	if !exact || i < 0 {
		return ""
	}
	return fmt.Sprintf(" — check at least %d bytes first (ctx.Check(off, %d)), or read inside the window", i+width, i+width)
}

// windowLoad lowers `w.U8(i)` and the like (i is a constant with i + width ≤ n — GB014). A receiver that is not a window returns nil.
func (l *lowerer) windowLoad(call *ast.CallExpr) (value, bool, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return value{}, false, false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return value{}, false, false
	}
	wv, _ := l.a.info.Uses[recv].(*types.Var)
	win, isWin := l.windows[wv]
	if !isWin {
		if wv != nil && isBPFNamed(wv.Type(), "Window") {
			l.fail(Rejected, GB005NilCheckShape, recv.Pos(), "window %s is used outside its `ok` branch", recv.Name)
			return value{}, false, true
		}
		return value{}, false, false
	}
	spec, known := windowLoads[sel.Sel.Name]
	if !known {
		return value{}, false, false // a method not in the table is checkEBPFSide's
	}
	if packetGenCheck && win.gen != l.pktGen { // an old window after Adjust
		l.liveWindow(recv, wv)
		return value{}, false, true
	}
	itv := l.a.info.Types[call.Args[0]]
	if itv.Value == nil {
		l.fail(Rejected, GB006NonConstant, call.Args[0].Pos(), "the index of %s.%s must be a constant (variable packet offsets use ctx.Check)", recv.Name, sel.Sel.Name)
		return value{}, false, true
	}
	i, exact := constant.Int64Val(constant.ToInt(itv.Value))
	width := int64(spec.bits / 8)
	if !exact || i < 0 || i > win.n-width {
		l.fail(Rejected, GB014WindowIndex, call.Args[0].Pos(), "%s.%s(%s) reads bytes [%s, %s+%d) outside the checked window of %d bytes%s", recv.Name, sel.Sel.Name, itv.Value.ExactString(), itv.Value.ExactString(), itv.Value.ExactString(), width, win.n, windowFix(exact, i, width))
		return value{}, false, true
	}
	t := vtype{bits: spec.bits}
	r := l.val()
	l.emit("%s = ebpf.packet.window_load %s[%d] : !ebpf.pkt_window<%d> -> %s", r, win.name, i, win.n, t.mlir())
	if spec.be && spec.bits > 8 {
		r2 := l.val()
		l.emit("%s = ebpf.byteorder.from_be %s : %s", r2, r, t.mlir())
		r = r2
	}
	return value{r, t}, true, true
}
