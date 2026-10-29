package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// Bounded loops.
//
//	for i := range uint32(N) { … }                 → ebpf.loop N unroll (carried…)
//	for i := T(0); i < N; i++ { … }                → ebpf.loop N unroll (carried…)
//	for i := T(0); i < n && i < N; i++ { … }       → ebpf.loop N unroll bound(%n) (carried…)   (a negative int32 n runs 0 times — as in Go)
//
// N is a constant 0..64, T is uint32 / int32 (the IV is i32). The default mode is **(U) unrolling** (`//gobpf:loop` selects (B) / (H) — loopmode.go; no automatic fallback).
// Assigning a variable from outside the loop in the body makes a loop-carried value (iter_args — bool is carried as i8). break / continue only as the last statement of an if arm (an unconditional
// break directly in the body is refused — a review point). What bpf-mlir does not allow in a body (a packet window from outside the loop, checked pointers, ring buffers)
// the frontend stops first with a position (GB018).

const (
	loopMaxCount   = 64   // the limit of N in bpf-mlir's ebpf.loop
	loopMaxDepth   = 2    // nesting depth
	loopMaxProduct = 64   // product of nested N
	unrollMaxOps   = 4096 // the limit of the (U) unrolling size estimate (the same as bpf-mlir's verifier)
)

// loopCtx is the state of an enclosing loop (the values at break / continue).
type loopCtx struct {
	carried  []*types.Var
	count    int64
	iv       *types.Var // the loop variable (nil for `for range N`) — shape B of variable indexes into record arrays
	backedge bool       // a (B) loop from `//gobpf:loop backedge` (ctx.Check in the body is GB018)
}

// liveEnvs returns only the envs of arms that did not escape (they go into the merge).
func liveEnvs(envs []map[*types.Var]value, escaped []bool) []map[*types.Var]value {
	var out []map[*types.Var]value
	for i, e := range envs {
		if !escaped[i] {
			out = append(out, e)
		}
	}
	return out
}

// loopShape returns the IV, count, runtime limit expression and body if s is an accepted bounded loop shape. Otherwise it returns the reason (reason ≠ "").
func (a *analyzer) loopShape(s ast.Stmt) (iv *types.Var, count int64, bound ast.Expr, body *ast.BlockStmt, reason string) {
	constCount := func(e ast.Expr) (int64, string) {
		tv := a.info.Types[e]
		if tv.Value == nil {
			return 0, "the loop bound must be a constant (at most 64) — a runtime bound is written `i < n && i < N`"
		}
		n, exact := constant.Int64Val(constant.ToInt(tv.Value))
		if !exact || n < 0 || n > loopMaxCount {
			return 0, fmt.Sprintf("the loop bound %s is outside [0, %d] (bpf-mlir's ebpf.loop)", tv.Value.ExactString(), loopMaxCount)
		}
		return n, ""
	}
	ivType := func(v *types.Var) string {
		if b, ok := v.Type().Underlying().(*types.Basic); ok && (b.Kind() == types.Uint32 || b.Kind() == types.Int32) {
			return ""
		}
		return fmt.Sprintf("the loop variable %s has type %s — it must be uint32 or int32 (the loop counter is i32)", v.Name(), v.Type())
	}
	switch s := s.(type) {
	case *ast.RangeStmt:
		if s.Value != nil || s.Tok == token.ASSIGN {
			return nil, 0, nil, nil, "only `for i := range N` (a constant integer N) is supported"
		}
		if tv := a.info.Types[s.X]; tv.Type == nil || tv.Value == nil {
			return nil, 0, nil, nil, "only `for i := range N` over a constant integer is supported (no range over slices, maps, strings or channels)"
		}
		n, why := constCount(s.X)
		if why != "" {
			return nil, 0, nil, nil, why
		}
		if id, ok := s.Key.(*ast.Ident); ok && id.Name != "_" {
			iv, _ = a.info.Defs[id].(*types.Var)
			if why := ivType(iv); why != "" {
				return nil, 0, nil, nil, why
			}
		}
		return iv, n, nil, s.Body, ""
	case *ast.ForStmt:
		const form = "the supported loops are `for i := range N`, `for i := T(0); i < N; i++` and `for i := T(0); i < n && i < N; i++` (N a constant ≤ 64)"
		init, _ := s.Init.(*ast.AssignStmt)
		post, _ := s.Post.(*ast.IncDecStmt)
		if init == nil || post == nil || s.Cond == nil || init.Tok != token.DEFINE || len(init.Lhs) != 1 || len(init.Rhs) != 1 || post.Tok != token.INC {
			return nil, 0, nil, nil, form
		}
		id, _ := init.Lhs[0].(*ast.Ident)
		if id == nil {
			return nil, 0, nil, nil, form
		}
		iv, _ = a.info.Defs[id].(*types.Var)
		if iv == nil {
			return nil, 0, nil, nil, form
		}
		if why := ivType(iv); why != "" {
			return nil, 0, nil, nil, why
		}
		if tv := a.info.Types[init.Rhs[0]]; tv.Value == nil || constant.Sign(tv.Value) != 0 {
			return nil, 0, nil, nil, "the loop variable must start at 0 (" + form + ")"
		}
		if pid, ok := post.X.(*ast.Ident); !ok || a.info.Uses[pid] != iv {
			return nil, 0, nil, nil, form
		}
		isIVLess := func(e ast.Expr) (ast.Expr, bool) {
			be, ok := e.(*ast.BinaryExpr)
			if !ok || be.Op != token.LSS {
				return nil, false
			}
			if x, ok := be.X.(*ast.Ident); !ok || a.info.Uses[x] != iv {
				return nil, false
			}
			return be.Y, true
		}
		if y, ok := isIVLess(s.Cond); ok {
			n, why := constCount(y)
			if why != "" {
				return nil, 0, nil, nil, why
			}
			return iv, n, nil, s.Body, ""
		}
		if be, ok := s.Cond.(*ast.BinaryExpr); ok && be.Op == token.LAND {
			rt, ok1 := isIVLess(be.X)
			ct, ok2 := isIVLess(be.Y)
			if ok1 && ok2 {
				n, why := constCount(ct)
				if why != "" {
					return nil, 0, nil, nil, why
				}
				return iv, n, rt, s.Body, ""
			}
		}
		return nil, 0, nil, nil, form
	}
	return nil, 0, nil, nil, "not a loop"
}

// assignedOuter returns the local variables from outside the loop assigned in the body (in declaration order). An assignment to the IV is returned as reason.
func (l *lowerer) assignedOuter(body *ast.BlockStmt, iv *types.Var) ([]*types.Var, token.Pos) {
	seen := map[*types.Var]bool{}
	var out []*types.Var
	var ivAssign token.Pos
	mark := func(e ast.Expr) {
		id, ok := e.(*ast.Ident)
		if !ok {
			return
		}
		v, _ := l.a.info.Uses[id].(*types.Var)
		if v == nil {
			return
		}
		if v == iv {
			ivAssign = id.Pos()
			return
		}
		if _, outer := l.env[v]; outer && !seen[v] && (v.Pos() < body.Pos() || v.Pos() > body.End()) {
			seen[v] = true
			out = append(out, v)
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if n.Tok != token.DEFINE {
				for _, lhs := range n.Lhs {
					mark(lhs)
				}
			}
		case *ast.IncDecStmt:
			mark(n.X)
		}
		return true
	})
	sortVars(out)
	return out, ivAssign
}

func sortVars(vs []*types.Var) {
	for i := range vs {
		for j := i + 1; j < len(vs); j++ {
			if vs[j].Pos() < vs[i].Pos() {
				vs[i], vs[j] = vs[j], vs[i]
			}
		}
	}
}

// loopStmt turns an accepted loop into ebpf.loop ((U) by default, (B) / (H) by directive).
func (l *lowerer) loopStmt(s ast.Stmt) {
	iv, count, boundE, body, why := l.a.loopShape(s)
	if why != "" {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "%s", why)
		return
	}
	product := count
	for _, c := range l.loops {
		product *= c.count
	}
	if len(l.loops)+1 > loopMaxDepth {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "loops nest at most %d deep (bpf-mlir's ebpf.loop)", loopMaxDepth)
		return
	}
	if product > loopMaxProduct {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "the nested loop counts multiply to %d — at most %d (bpf-mlir's ebpf.loop)", product, loopMaxProduct)
		return
	}
	// An unconditional break / continue directly in the body (a review point).
	if n := len(body.List); n > 0 {
		if br, ok := body.List[n-1].(*ast.BranchStmt); ok {
			l.fail(Rejected, GB018LoopShape, br.Pos(), "an unconditional %s at the end of the loop body — the loop would run once (or the %s does nothing); write the condition as `if … { %s }`", br.Tok, br.Tok, br.Tok)
			return
		}
	}
	// What bpf-mlir does not let into a body: packet windows and checked pointers (references across the loop), and for a (H) callback also the context.
	callback := l.a.loopMode[s] == "callback"
	bad := false
	ast.Inspect(body, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok || bad {
			return !bad
		}
		v, _ := l.a.info.Uses[id].(*types.Var)
		if callback && v != nil && isContextType(v.Type()) {
			l.fail(Rejected, GB018LoopShape, id.Pos(), "the context cannot be used inside a `//gobpf:loop callback` loop (bpf_loop's callback receives only integers and map handles) — read what you need from %s before the loop, or drop the directive", id.Name)
			bad = true
			return false
		}
		if _, isWin := l.windows[v]; isWin && v != nil {
			l.fail(Rejected, GB018LoopShape, id.Pos(), "the packet window %s cannot be used inside a loop (bpf-mlir: a loop carries only integers, the context and map handles) — read the bytes before the loop", id.Name)
			bad = true
		}
		if l.borrowOf(v) != nil {
			l.fail(Rejected, GB018LoopShape, id.Pos(), "the checked pointer %s cannot be used inside a loop (a reference cannot cross the loop) — read the value before the loop or Lookup inside it", id.Name)
			bad = true
		}
		return !bad
	})
	if bad {
		return
	}
	carried, ivAssign := l.assignedOuter(body, iv)
	if ivAssign.IsValid() {
		l.fail(Rejected, GB018LoopShape, ivAssign, "the loop variable %s must not be assigned in the body", iv.Name())
		return
	}
	defer l.at(s.Pos())()
	// The runtime limit (bound): an i32 evaluated once at entry. A negative int32 n runs 0 times in Go — make it 0 before the unsigned min(n, N).
	boundText := ""
	if boundE != nil {
		for _, v := range carried {
			ast.Inspect(boundE, func(n ast.Node) bool {
				if id, ok := n.(*ast.Ident); ok && l.a.info.Uses[id] == v {
					l.fail(Rejected, GB018LoopShape, id.Pos(), "the runtime bound uses %s, which the body assigns — Go re-reads it every iteration, ebpf.loop reads it once", v.Name())
				}
				return true
			})
		}
		if !l.pure(boundE) {
			l.fail(Rejected, GB018LoopShape, boundE.Pos(), "the runtime bound must have no side effects (it is evaluated once at the loop entry)")
		}
		if l.failed {
			return
		}
		ivT := vtype{bits: 32, signed: isSigned(iv.Type())}
		n, ok := l.expr(boundE, &ivT)
		if !ok {
			return
		}
		name := n.name
		if ivT.signed {
			z := l.constant(constant.MakeInt64(0), ivT)
			neg := l.val()
			l.emit("%s = arith.cmpi slt, %s, %s : i32", neg, n.name, z.name)
			clamped := l.val()
			thenT := l.region(func() { l.emit("ebpf.if.yield %s : i32", z.name) })
			elseT := l.region(func() { l.emit("ebpf.if.yield %s : i32", n.name) })
			l.b.WriteString(fmt.Sprintf("%s%s = ebpf.if %s -> i32 {\n%s%s} else {\n%s%s}%s\n", l.indent, clamped, neg, thenT, l.indent, elseT, l.indent, l.locSuffix(boundE.Pos())))
			name = clamped
		}
		boundText = " bound(" + name + ")"
	}
	// Initial values of loop-carried values (bool is i8).
	before := copyEnv(l.env)
	var inits, types_ []string
	for _, v := range carried {
		c := l.toCarrier(before[v])
		inits = append(inits, c.name)
		types_ = append(types_, c.t.mlir())
	}
	ivName := l.val()
	var args []string
	argNames := make([]string, len(carried))
	for i := range carried {
		argNames[i] = l.val()
		args = append(args, fmt.Sprintf("%s: %s", argNames[i], types_[i]))
	}
	backedge := l.a.loopMode[s] == "backedge"
	ctx := &loopCtx{carried: carried, count: count, iv: iv, backedge: backedge}
	savedArm := l.checkArmDepth // break / continue in the body leave this loop — they do not cross a region even inside an outer Check arm
	l.checkArmDepth = 0
	defer func() { l.checkArmDepth = savedArm }()
	l.env = copyEnv(before)
	l.loops = append(l.loops, ctx)
	l.escaped = false
	bodyText := l.region(func() {
		if iv != nil {
			l.env[iv] = value{ivName, vtype{bits: 32, signed: isSigned(iv.Type())}}
			if count > 0 {
				l.bounds[ivName] = uint64(count - 1) // the loop variable's upper bound
			}
		}
		for i, v := range carried {
			l.env[v] = l.fromCarrier(argNames[i], before[v].t)
		}
		l.stmts(body.List)
		if l.failed {
			return
		}
		defer l.at(body.Rbrace)()
		l.emit("%s", l.branchText("ebpf.loop.yield", carried))
	})
	l.loops = l.loops[:len(l.loops)-1]
	l.escaped = false
	l.env = before
	if l.failed {
		return
	}
	// The (U) unrolling size — counted the same way as bpf-mlir's loopCost (estimate.go).
	bodyEst, cost, err := unrollEstimate(bodyText, count)
	if err != nil {
		l.fail(Unknown, GB015InternalEmitter, s.Pos(), "internal: the unroll estimate cannot read the loop body (%v) — this is a gobpf frontend bug, please report it", err)
		return
	}
	if cost > unrollMaxOps && unrollLimitCheck && !backedge && !callback { // (B) / (H) do not unroll — no estimate
		l.fail(Rejected, GB018LoopShape, s.Pos(), "unrolling a body estimated at %d op(s) (+%d per copy) %d times is estimated at more than %d op(s) — bpf-mlir's limit for an unrolled loop (lower the count or shrink the body)", bodyEst, unrollCopyOverhead, count, unrollMaxOps)
		return
	}
	typeSig := "(" + strings.Join(types_, ", ") + ") -> "
	if len(types_) == 1 {
		typeSig += types_[0]
	} else {
		typeSig += "(" + strings.Join(types_, ", ") + ")"
	}
	head, base := "", ""
	if len(carried) > 0 {
		base = l.val()
		head = base + " = "
		if len(carried) > 1 {
			head = fmt.Sprintf("%s:%d = ", base, len(carried))
		}
	}
	mode := " unroll"
	if backedge {
		mode = "" // (B) — bpf-mlir's default mode (a bounded back-edge)
	}
	if callback {
		mode = " callback" // (H) — the bpf_loop helper and a static callback
	}
	l.b.WriteString(fmt.Sprintf("%s%sebpf.loop %d%s%s (%s) : %s {\n%s^bb0(%s):\n%s%s}%s\n",
		l.indent, head, count, mode, boundText, strings.Join(inits, ", "), typeSig, l.indent, strings.Join(append([]string{ivName + ": i32"}, args...), ", "), bodyText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(carried, before, base)
	}
}

// branchText returns the text of break / continue / loop.yield (passing loop-carried values, with bool widened to i8).
func (l *lowerer) branchText(op string, carried []*types.Var) string {
	var names, typs []string
	for _, v := range carried {
		c := l.toCarrier(l.env[v])
		names = append(names, c.name)
		typs = append(typs, c.t.mlir())
	}
	if len(names) == 0 {
		return op
	}
	return fmt.Sprintf("%s %s : %s", op, strings.Join(names, ", "), strings.Join(typs, ", "))
}

// branch lowers a break / continue at the end of an if arm (stmts checks the position).
func (l *lowerer) branch(s *ast.BranchStmt) {
	if s.Label != nil || (s.Tok != token.BREAK && s.Tok != token.CONTINUE) {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "%s is not supported (only unlabeled break / continue inside a loop)", s.Tok)
		return
	}
	if len(l.loops) == 0 {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "%s outside a loop", s.Tok)
		return
	}
	if l.checkArmDepth > 0 {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "%s inside a ctx.Check branch must be the last statement of that branch (it leaves the loop through the check's exit code); move the condition out of the branch", s.Tok)
		return
	}
	op := "ebpf.break"
	if s.Tok == token.CONTINUE {
		op = "ebpf.continue"
	}
	l.emit("%s", l.branchText(op, l.loops[len(l.loops)-1].carried))
	l.escaped = true
}

func isSigned(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsUnsigned == 0
}

// boundedLoopForm is the syntactic shape used by the capability check (range over a constant integer, or a three-clause for with := init and ++ post).
func (a *analyzer) boundedLoopForm(s ast.Stmt) bool {
	switch s := s.(type) {
	case *ast.RangeStmt:
		tv := a.info.Types[s.X]
		return tv.Value != nil && tv.Value.Kind() == constant.Int
	case *ast.ForStmt:
		init, _ := s.Init.(*ast.AssignStmt)
		post, _ := s.Post.(*ast.IncDecStmt)
		return init != nil && init.Tok == token.DEFINE && post != nil && post.Tok == token.INC && s.Cond != nil
	}
	return false
}
