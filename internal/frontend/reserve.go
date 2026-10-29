package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// Ring buffer reservations (bpf-mlir's ringbuf.reserve):
//
//	if e, ok := Events.Reserve(); ok {       → %r = ebpf.ringbuf.reserve "Events" : !ebpf.maybe_reservation<R>
//		e.Kind = k                             → ebpf.ringbuf.store_field %res[0], %k : !ebpf.reservation<R>, i32
//		*e = Ev{…}                             → ebpf.ringbuf.store_record %res, %made : !ebpf.reservation<R>, R
//		Events.Submit(e) / Events.Discard(e)   → ebpf.ringbuf.submit / discard %res : !ebpf.reservation<R>
//	} else { … }                             → ebpf.ringbuf.if_reserved %r … present { ^present(%res): … } absent { … }
//
// The frontend owns only **the Go shape rules**: Reserve is in the init statement of an if whose condition is ok itself, and e is used only in integer field assignments,
// `*e = V{…}` and as the argument of Submit / Discard (a read, an assignment to another variable, passing to a function, the else arm, inside a loop and defer are GB). **The consume count**
// (exactly once on every path, no assignment after consuming) is checked by bpf-mlir's ebpf-verify-ownership, and its errors appear at the Go position through ebpf-compile's loc.

// reservation is the reservation of the present arm (the variable e, the block argument, the map, the loop depth at Reserve).
type reservation struct {
	obj   *types.Var
	res   string
	m     *BpfMap
	loops int
}

// reserveCall returns the map if call is RingBuf.Reserve.
func (l *lowerer) reserveCall(e ast.Expr) (*BpfMap, bool) {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	m, en, _, known := l.mapMethod(call)
	return m, m != nil && known && en.op == "ringbuf_reserve"
}

// isReserveIf reports whether s is `if e, ok := M.Reserve(); …`.
func (l *lowerer) isReserveIf(s *ast.IfStmt) bool {
	as, ok := s.Init.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return false
	}
	_, isRes := l.reserveCall(as.Rhs[0])
	return isRes
}

// ifReserve lowers `if e, ok := M.Reserve(); ok { … } [else { … }]` to if_reserved.
func (l *lowerer) ifReserve(s *ast.IfStmt) {
	as := s.Init.(*ast.AssignStmt)
	call := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
	m, _ := l.reserveCall(call)
	shape := func(p token.Pos, what string) {
		l.fail(Rejected, GB005NilCheckShape, p, "%s — the supported form is `if e, ok := %s.Reserve(); ok { …; %s.Submit(e) / %s.Discard(e) } [else { … }]`", what, m.Symbol, m.Symbol, m.Symbol)
	}
	if len(as.Lhs) != 2 || as.Tok != token.DEFINE {
		shape(as.Pos(), "the if statement's init must be `e, ok := "+m.Symbol+".Reserve()`")
		return
	}
	eid, _ := as.Lhs[0].(*ast.Ident)
	okid, _ := as.Lhs[1].(*ast.Ident)
	if eid == nil || okid == nil || eid.Name == "_" || okid.Name == "_" {
		shape(as.Pos(), "both results of Reserve must be named (`e, ok := …`)")
		return
	}
	eobj, _ := l.a.info.Defs[eid].(*types.Var)
	okobj, _ := l.a.info.Defs[okid].(*types.Var)
	if cid, isID := ast.Unparen(s.Cond).(*ast.Ident); !isID || l.a.info.Uses[cid] != okobj {
		shape(s.Cond.Pos(), "the condition must be exactly `"+okid.Name+"`")
		return
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.Reserve cannot be inside a loop (bpf-mlir does not allow ring buffer ops in a loop body)", m.Symbol)
		return
	}
	if l.resv != nil {
		l.fail(Rejected, GB005NilCheckShape, call.Pos(), "%s.Reserve inside the reserved branch of %s — one reservation at a time", m.Symbol, l.resv.obj.Name())
		return
	}
	if m.Value.Kind != ABIRecord {
		l.fail(Unknown, GB016SharedABIShape, call.Pos(), "%s.Reserve needs a record event type (the ring buffer's V)", m.Symbol)
		return
	}
	var elseBlock *ast.BlockStmt
	if s.Else != nil {
		eb, isBlock := s.Else.(*ast.BlockStmt)
		if !isBlock {
			shape(s.Else.Pos(), "else-if is not supported")
			return
		}
		elseBlock = eb
		ast.Inspect(eb, func(x ast.Node) bool {
			if id, isID := x.(*ast.Ident); isID && l.a.info.Uses[id] == eobj {
				l.fail(Rejected, GB005NilCheckShape, id.Pos(), "%s is not reserved in the else branch (the ring buffer had no room) — use it only in the `if %s { … }` branch", id.Name, okid.Name)
			}
			return true
		})
		if l.failed {
			return
		}
	}
	defer l.at(call.Pos())()
	rt := m.Value.mlir()
	r := l.val()
	l.emit("%s = ebpf.ringbuf.reserve %q : !ebpf.maybe_reservation<%s>", r, m.Symbol, rt)
	res := l.val()
	if l.resvVars == nil {
		l.resvVars = map[*types.Var]bool{}
	}
	l.resvVars[eobj] = true
	before := copyEnv(l.env)
	l.env = copyEnv(before)
	l.escaped = false
	l.resv = &reservation{obj: eobj, res: res, m: m, loops: len(l.loops)}
	presentText := l.region(func() { l.stmts(s.Body.List) })
	l.resv = nil
	presentEnv, presentEsc := l.env, l.escaped
	l.env = copyEnv(before)
	l.escaped = false
	absentText := ""
	if elseBlock != nil {
		absentText = l.region(func() { l.stmts(elseBlock.List) })
	}
	absentEnv, absentEsc := l.env, l.escaped
	l.escaped = false
	if l.failed {
		return
	}
	mods := mergeVars(before, liveEnvs([]map[*types.Var]value{presentEnv, absentEnv}, []bool{presentEsc, absentEsc})...)
	absentPos := s.Body.Rbrace
	if elseBlock != nil {
		absentPos = elseBlock.Rbrace
	}
	if !presentEsc {
		l.yieldInto(&presentText, presentEnv, mods, "ebpf.yield", s.Body.Rbrace)
	}
	if !absentEsc {
		l.yieldInto(&absentText, absentEnv, mods, "ebpf.yield", absentPos)
	}
	l.env = before
	head, typeList, base := l.resultHead(mods, before)
	l.b.WriteString(fmt.Sprintf("%s%sebpf.ringbuf.if_reserved %s : !ebpf.maybe_reservation<%s>%s present {\n%s^present(%s: !ebpf.reservation<%s>):\n%s%s} absent {\n%s%s}%s\n",
		l.indent, head, r, rt, typeList, l.indent, res, rt, presentText, l.indent, absentText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(mods, before, base)
	}
}

// resvOf returns the reservation variable if e is (an identifier of) it.
func (l *lowerer) resvOf(e ast.Expr) *types.Var {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return nil
	}
	v, _ := l.a.info.Uses[id].(*types.Var)
	if v != nil && l.resvVars[v] {
		return v
	}
	return nil
}

// resvPlace checks that a write / consume of a reservation is on the reservation of the current present arm and not inside a loop.
func (l *lowerer) resvPlace(v *types.Var, at token.Pos, what string) bool {
	if l.resv == nil || l.resv.obj != v {
		l.fail(Rejected, GB005NilCheckShape, at, "%s of %s outside its `if %s, ok := ….Reserve(); ok { … }` branch", what, v.Name(), v.Name())
		return false
	}
	if len(l.loops) > l.resv.loops {
		l.fail(Rejected, GB018LoopShape, at, "%s of %s inside a loop (bpf-mlir does not allow a live reservation across a loop)", what, v.Name())
		return false
	}
	return true
}

// reserveAssign lowers `e.F = v` (store_field — an integer field) and `*e = V{…}` (store_record) in the present arm.
// handled reports whether s is an assignment to a reservation (using Reserve outside the init statement of an if also stops here).
func (l *lowerer) reserveAssign(s *ast.AssignStmt) bool {
	for _, r := range s.Rhs {
		if m, isRes := l.reserveCall(r); isRes {
			l.fail(Rejected, GB005NilCheckShape, r.Pos(), "%s.Reserve may only be the init of an if statement: `if e, ok := %s.Reserve(); ok { … }`", m.Symbol, m.Symbol)
			return true
		}
	}
	for _, r := range s.Rhs { // a read of the reserved event or an assignment to another variable (`g := e`, `x := e.F`, `*e` as a value) — named before the other rules
		if l.resvScan(r) {
			return true
		}
	}
	if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	switch lhs := ast.Unparen(s.Lhs[0]).(type) {
	case *ast.SelectorExpr:
		v := l.resvOf(lhs.X)
		if v == nil {
			return false
		}
		defer l.at(s.Pos())()
		if s.Tok != token.ASSIGN {
			l.fail(Rejected, GB005NilCheckShape, s.Pos(), "%s.%s %s …: a reserved event can only be assigned (`=`) — it cannot be read", v.Name(), lhs.Sel.Name, s.Tok)
			return true
		}
		if !l.resvPlace(v, s.Pos(), "assignment to a field") {
			return true
		}
		m := l.resv.m
		f, ok := m.Value.Record.fieldByGoName(lhs.Sel.Name)
		if !ok || f.Type.Kind != ABIInt {
			l.fail(Rejected, GB016SharedABIShape, lhs.Sel.Pos(), "%s.%s: only the integer fields of the event %s can be written one by one (write a record field or array with `*%s = %s{…}`)", v.Name(), lhs.Sel.Name, m.Value.Record.Symbol, v.Name(), m.Value.Record.Symbol)
			return true
		}
		t := vtypeOf(*f.Type.Int)
		val, ok := l.expr(s.Rhs[0], &t) // Go's type check forces the field's type
		if !ok {
			return true
		}
		l.emit("ebpf.ringbuf.store_field %s[%d], %s : !ebpf.reservation<%s>, %s", l.resv.res, f.Offset, val.name, m.Value.mlir(), t.mlir())
		return true
	case *ast.StarExpr:
		v := l.resvOf(lhs.X)
		if v == nil {
			return false
		}
		defer l.at(s.Pos())()
		if s.Tok != token.ASSIGN || !l.resvPlace(v, s.Pos(), "assignment to the event") {
			if s.Tok != token.ASSIGN {
				l.fail(Rejected, GB005NilCheckShape, s.Pos(), "*%s %s …: a reserved event can only be assigned (`=`)", v.Name(), s.Tok)
			}
			return true
		}
		m := l.resv.m
		made, ok := l.recordMake(s.Rhs[0], m.Value)
		if !ok {
			return true
		}
		rt := m.Value.mlir()
		l.emit("ebpf.ringbuf.store_record %s, %s : !ebpf.reservation<%s>, %s", l.resv.res, made, rt, rt)
		return true
	}
	return false
}

// reserveConsume lowers `M.Submit(e)` / `M.Discard(e)` (the consume) in the present arm. handled reports whether call is that call.
func (l *lowerer) reserveConsume(call *ast.CallExpr) bool {
	m, en, name, known := l.mapMethod(call)
	if m == nil || !known || (en.op != "ringbuf_submit" && en.op != "ringbuf_discard") {
		return false
	}
	defer l.at(call.Pos())()
	v := l.resvOf(call.Args[0])
	if v == nil {
		l.fail(Rejected, GB005NilCheckShape, call.Args[0].Pos(), "the argument of %s.%s must be the reserved event `e` of `if e, ok := %s.Reserve(); ok { … }`", m.Symbol, name, m.Symbol)
		return true
	}
	if !l.resvPlace(v, call.Pos(), m.Symbol+"."+name) {
		return true
	}
	if l.resv.m != m {
		l.fail(Rejected, GB005NilCheckShape, call.Pos(), "%s was reserved in %s, not %s", v.Name(), l.resv.m.Symbol, m.Symbol)
		return true
	}
	op := map[string]string{"ringbuf_submit": "submit", "ringbuf_discard": "discard"}[en.op]
	l.emit("ebpf.ringbuf.%s %s : !ebpf.reservation<%s>", op, l.resv.res, m.Value.mlir())
	return true
}

// resvScan looks for uses of a reservation variable (a read, passing it) in n and stops with a GB error if found (true). The caller excludes Submit / Discard arguments and assignment left-hand sides.
func (l *lowerer) resvScan(n ast.Node) bool {
	if len(l.resvVars) == 0 {
		return false
	}
	found := false
	ast.Inspect(n, func(x ast.Node) bool {
		if found {
			return false
		}
		if e, ok := x.(ast.Expr); ok && l.resvUse(e) {
			found = true
			return false
		}
		return true
	})
	return found
}

// resvUse stops a use of a reservation variable in an expression (a read, an assignment to another variable, passing to a function). handled reports whether e is such a use.
func (l *lowerer) resvUse(e ast.Expr) bool {
	var v *types.Var
	switch x := ast.Unparen(e).(type) {
	case *ast.Ident:
		v = l.resvOf(x)
	case *ast.SelectorExpr:
		v = l.resvOf(x.X)
	case *ast.StarExpr:
		v = l.resvOf(x.X)
	}
	if v == nil {
		return false
	}
	l.fail(Rejected, GB005NilCheckShape, e.Pos(), "a reserved event cannot be read or passed on — %s may only be written (`%s.F = v`, `*%s = …{…}`) and consumed (`….Submit(%s)` / `….Discard(%s)`)", v.Name(), v.Name(), v.Name(), v.Name(), v.Name())
	return true
}
