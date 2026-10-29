package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// Spin locks and timers (bpf-mlir's ebpf.spin.region and ebpf.timer.*).
//
//	if p := M.Lookup(k); p != nil {
//		bpf.WithLock(&p.Lock, func() { p.A++ })   → ebpf.spin.region %b "lock" : !ebpf.borrowed<R> { … ebpf.yield }
//		if st := p.T.Init(); st == 0 {             → %st = ebpf.timer.init %b "t", %m clock "monotonic" : …, … -> i64
//			_ = p.T.SetCallback(onFire)            → ebpf.timer.set_callback %b "t", @onFire : … -> i64
//			_ = p.T.Start(1_000_000)               → ebpf.timer.start %b "t", %ns : …, i64 -> i64
//		}
//	}
//	func onFire(v *R) { v.N++ }                    → ebpf.timer.callback @onFire map @M : !ebpf.record<R> { ^bb0(%v): … ebpf.timer.done }
//
// The ops only inside a Lookup branch of an xdp program body (what bpf-mlir's compiler supports — other kinds are compiler unsupported). The WithLock func and the callback body are
// closed regions (bpf-mlir's op verifier constraints on the Go line — calls, escapes, assignments to outer variables and other pointers are GB026).

// TimerCallback is a timer callback function (the argument of SetCallback).
type TimerCallback struct {
	Symbol string
	Pos    token.Position
	decl   *ast.FuncDecl
	obj    *types.Func
	param  *types.Var
	m      *BpfMap // the bound map (the Lookup map of the first SetCallback)
	mPos   token.Pos
	body   string
}

// callOp returns the op if call is a call of the gobpf API.
func (l *lowerer) callOp(call *ast.CallExpr) string {
	var obj types.Object
	fun := ast.Unparen(call.Fun)
	if ix, ok := fun.(*ast.IndexExpr); ok { // a generic function with explicit type arguments (bpf.TPArg[T])
		fun = ix.X
	}
	switch f := fun.(type) {
	case *ast.SelectorExpr:
		obj = l.a.info.Uses[f.Sel]
	case *ast.Ident:
		obj = l.a.info.Uses[f]
	}
	if obj == nil || !inAPIPackage(obj) {
		return ""
	}
	e, ok := lookupAPI(obj)
	if !ok {
		return ""
	}
	return e.op
}

func isTimerOp(op string) bool {
	return op == "timer_init" || op == "timer_set_callback" || op == "timer_start"
}

// lockTimerPlace checks that a lock / timer op is inside a Lookup branch of an xdp program body (otherwise it reports and returns false).
func (l *lowerer) lockTimerPlace(p token.Pos, what string) bool {
	if l.progKind == nil || l.progKind.Kind != "xdp" || l.prog == nil {
		kind := "subprogram"
		if l.progKind != nil && l.prog != nil {
			kind = l.progKind.Kind + " program"
		}
		if l.callback != nil {
			kind = "timer callback"
		}
		l.fail(Rejected, GB026LockTimerShape, p, "%s may only be used in the body of an xdp program (bpf-mlir supports spin locks and timers in xdp programs only) — not in a %s", what, kind)
		return false
	}
	hasRec := false
	for _, c := range l.borrows {
		hasRec = hasRec || c.rec != nil
	}
	if !hasRec {
		l.fail(Rejected, GB026LockTimerShape, p, "%s needs the checked map value: write it inside `if p := M.Lookup(k); p != nil { … }`", what)
		return false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, p, "%s cannot be inside a loop (bpf-mlir does not allow spin lock / timer ops in a loop body)", what)
		return false
	}
	return true
}

// specialOf returns the field and the borrow of p if e is a lock / timer field (`p.F`) of a checked p (outer or inner).
func (l *lowerer) specialOf(e ast.Expr, kind ABIKind) (FieldABI, *checkedRef, bool) {
	sel, ok := ast.Unparen(e).(*ast.SelectorExpr)
	if !ok {
		return FieldABI{}, nil, false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return FieldABI{}, nil, false
	}
	uv, _ := l.a.info.Uses[id].(*types.Var)
	c := l.borrowOf(uv)
	if c == nil || c.rec == nil {
		return FieldABI{}, nil, false
	}
	sp := c.rec.Record.Special
	if sp == nil || sp.GoName != sel.Sel.Name || sp.Type.Kind != kind {
		return FieldABI{}, nil, false
	}
	return *sp, c, true
}

// withLock lowers the statement `bpf.WithLock(&p.Lock, func() { … })` to ebpf.spin.region.
func (l *lowerer) withLock(call *ast.CallExpr) bool {
	if l.callOp(call) != "with_lock" {
		return false
	}
	defer l.at(call.Pos())()
	if !l.lockTimerPlace(call.Pos(), "bpf.WithLock") {
		return true
	}
	u, isAddr := ast.Unparen(call.Args[0]).(*ast.UnaryExpr)
	var fld FieldABI
	var lc *checkedRef
	ok := isAddr && u.Op == token.AND
	if ok {
		fld, lc, ok = l.specialOf(u.X, ABISpinLock)
	}
	if !ok {
		l.fail(Rejected, GB026LockTimerShape, call.Args[0].Pos(), "the first argument of bpf.WithLock must be &p.F — the bpf.SpinLock field of the checked map value p")
		return true
	}
	defer l.focus(lc)() // the region is closed over the lock's record only (checkRegion — even inside two borrows, the other borrow cannot be used in the region)
	fl, isLit := ast.Unparen(call.Args[1]).(*ast.FuncLit)
	if !isLit {
		l.fail(Rejected, GB026LockTimerShape, call.Args[1].Pos(), "the second argument of bpf.WithLock must be a func literal written in place (`func() { … }` — the closed critical region)")
		return true
	}
	if !l.checkRegion(fl.Body, fl, "bpf.WithLock's region", false) {
		return true
	}
	before := copyEnv(l.env)
	body := l.region(func() {
		l.stmts(fl.Body.List)
		defer l.at(fl.Body.Rbrace)()
		l.emit("ebpf.yield")
	})
	l.env = before // local variables in the region do not escape (spin.region returns no value)
	if l.failed {
		return true
	}
	l.b.WriteString(fmt.Sprintf("%sebpf.spin.region %s %q : %s {\n%s%s}%s\n", l.indent, lc.borrow, fld.Name, borrowType(lc), body, l.indent, l.locSuffix(call.Pos())))
	return true
}

// checkRegion checks the WithLock func and timer callback bodies: statements are only assignments and ++ / -- (the left-hand side is a ref field or a local variable of the region),
// expressions are integer arithmetic, conversions, ref fields and local variables (and bpf.KtimeNs in a callback). Anything else is GB026.
func (l *lowerer) checkRegion(body *ast.BlockStmt, scope ast.Node, what string, callback bool) bool {
	good := true
	bad := func(p token.Pos, format string, args ...any) {
		l.fail(Rejected, GB026LockTimerShape, p, format, args...)
		good = false
	}
	ref := l.checked.obj
	inside := func(obj types.Object) bool { return obj != nil && obj.Pos() >= scope.Pos() && obj.Pos() < scope.End() }
	lhsOK := func(e ast.Expr) {
		switch x := ast.Unparen(e).(type) {
		case *ast.Ident:
			if x.Name == "_" {
				return
			}
			if obj := l.a.info.Uses[x]; obj != nil && !inside(obj) {
				bad(x.Pos(), "%s cannot assign %s, a variable declared outside it (the region returns no values — declare the variable inside, or write a field of %s)", what, x.Name, ref.Name())
			}
		case *ast.SelectorExpr, *ast.IndexExpr:
			// a ref field (fieldPath checks it — the expression check below stops other pointers)
		default:
			bad(e.Pos(), "%s can only assign fields of %s and variables declared inside it", what, ref.Name())
		}
	}
	var stmts func(list []ast.Stmt)
	stmts = func(list []ast.Stmt) {
		for _, st := range list {
			switch s := st.(type) {
			case *ast.AssignStmt:
				if s.Tok != token.DEFINE {
					for _, e := range s.Lhs {
						lhsOK(e)
					}
				}
			case *ast.IncDecStmt:
				lhsOK(s.X)
			case *ast.IfStmt:
				// if in a timer callback (with else and nesting — the bodies recurse under the same rules; bpf-mlir's ebpf.if in a callback).
				if !callback {
					bad(st.Pos(), "%T cannot be inside %s — only assignments and ++ / -- of %s's fields and of local variables (no if / for / switch / blocks)", st, what, ref.Name())
					continue
				}
				if s.Init != nil {
					bad(s.Init.Pos(), "an if in %s cannot have an init statement — declare the value before the if", what)
					continue
				}
				stmts(s.Body.List)
				switch e := s.Else.(type) {
				case *ast.BlockStmt:
					stmts(e.List)
				case *ast.IfStmt:
					stmts([]ast.Stmt{e})
				}
			case *ast.ReturnStmt:
				bad(s.Pos(), "return cannot be inside %s (the region has one exit — it ends at its closing brace)", what)
			case *ast.BranchStmt:
				bad(s.Pos(), "%s cannot be inside %s (the region has one exit — it ends at its closing brace)", s.Tok, what)
			case *ast.DeferStmt:
				bad(s.Pos(), "defer cannot be inside %s", what)
			case *ast.ExprStmt:
				if c, ok := s.X.(*ast.CallExpr); ok {
					if id, ok := ast.Unparen(c.Fun).(*ast.Ident); ok && id.Name == "panic" {
						bad(s.Pos(), "panic cannot be inside %s", what)
						continue
					}
					if callback && l.callOp(c) == "timer_start" { // a statement discarding the status of Start in a callback
						l.fail(Rejected, GB017StatusIgnored, s.Pos(), "the raw status of Timer.Start in %s is discarded — use it (`st := %s.T.Start(ns)`) or discard it explicitly (`_ = …` — a failed restart ends the periodic timer silently)", what, ref.Name())
						good = false
						continue
					}
				}
				bad(s.Pos(), "a call statement cannot be inside %s (helpers and map operations are not allowed while the region runs)", what)
			default:
				extra := "no if / for / switch / blocks"
				if callback {
					extra = "and if — no for / switch / blocks"
				}
				bad(st.Pos(), "%T cannot be inside %s — only assignments and ++ / -- of %s's fields and of local variables (%s)", st, what, ref.Name(), extra)
			}
		}
	}
	stmts(body.List)
	if !good {
		return false
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.FuncLit:
			bad(x.Pos(), "a function literal cannot be inside %s", what)
			return false
		case *ast.CallExpr:
			if l.a.info.Types[x.Fun].IsType() {
				return true // a type conversion
			}
			if callback && l.callOp(x) == "ktime" {
				return true
			}
			if callback && l.callOp(x) == "timer_start" { // restarting its own timer (the Ident check below looks at the receiver pointer)
				return true
			}
			if callback && (l.callOp(x) == "timer_init" || l.callOp(x) == "timer_set_callback") {
				bad(x.Pos(), "Timer.%s cannot be inside %s — a callback may only restart its own timer with %s.T.Start(ns) (init and set_callback stay in the program)", sel(x), what, ref.Name())
				return false
			}
			allowed := "no calls"
			if callback {
				allowed = "only bpf.KtimeNs() and the Start of its own timer"
			}
			bad(x.Pos(), "a call cannot be inside %s (%s — helpers, map operations and subprograms are not allowed there)", what, allowed)
			return false
		case *ast.UnaryExpr:
			if x.Op == token.AND {
				bad(x.Pos(), "taking an address cannot be inside %s", what)
				return false
			}
		case *ast.StarExpr:
			bad(x.Pos(), "a pointer dereference cannot be inside %s", what)
			return false
		case *ast.Ident:
			if v, ok := l.a.info.Uses[x].(*types.Var); ok && v != ref {
				if _, isPtr := v.Type().(*types.Pointer); isPtr {
					bad(x.Pos(), "%s can only use the pointer %s, not %s", what, ref.Name(), x.Name)
				}
				if l.a.mapByObj[v] != nil {
					bad(x.Pos(), "map %s cannot be used inside %s", x.Name, what)
				}
			}
		}
		return true
	})
	return good
}

// timerCall lowers `p.T.Init()` / `p.T.SetCallback(cb)` / `p.T.Start(ns)` to ebpf.timer.*. handled reports whether call is one of them.
func (l *lowerer) timerCall(call *ast.CallExpr) (value, bool, bool) {
	op := l.callOp(call)
	if !isTimerOp(op) {
		return value{}, false, false
	}
	defer l.at(call.Pos())()
	name := sel(call)
	what := "Timer." + name
	if l.callback != nil && op == "timer_start" { // restarting its own timer in a callback (no Init guard needed — a callback runs only when a started timer fires)
		recv := ast.Unparen(call.Fun).(*ast.SelectorExpr).X
		fld, tc, ok := l.specialOf(recv, ABITimer)
		if !ok || tc.obj != l.callback.param {
			l.fail(Rejected, GB026LockTimerShape, recv.Pos(), "Timer.Start in the timer callback %s must restart its own timer, `%s.T.Start(ns)`", l.callback.Symbol, l.callback.param.Name())
			return value{}, false, true
		}
		ns, ok := l.expr(call.Args[0], &vtype{bits: 64})
		if !ok {
			return value{}, false, true
		}
		r := l.val()
		l.emit("%s = ebpf.timer.start %s %q, %s : %s, i64 -> i64", r, tc.borrow, fld.Name, ns.name, borrowType(tc))
		return value{r, vtype{bits: 64, signed: true}}, true, true
	}
	if !l.lockTimerPlace(call.Pos(), what) {
		return value{}, false, true
	}
	recv := ast.Unparen(call.Fun).(*ast.SelectorExpr).X
	fld, tc, ok := l.specialOf(recv, ABITimer)
	if !ok {
		l.fail(Rejected, GB026LockTimerShape, recv.Pos(), "Timer.%s must be called on the bpf.Timer field of the checked map value (`p.T.%s(…)` inside `if p := M.Lookup(k); p != nil`)", name, name)
		return value{}, false, true
	}
	defer l.focus(tc)() // timer ops are closed over the borrow of p (the Init map, the callback record — even inside two borrows)
	b, bt := tc.borrow, borrowType(tc)
	r := l.val()
	i64 := vtype{bits: 64, signed: true}
	switch op {
	case "timer_init":
		m := l.checked.m
		l.emit("%s = ebpf.timer.init %s %q, %s clock %q : %s, %s -> i64", r, b, fld.Name, l.mapArgs[m], "monotonic", bt, l.mapType(m))
		return value{r, i64}, true, true
	case "timer_set_callback", "timer_start":
		if !l.a.inInitGuard(call.Pos(), l.checked.obj) {
			l.fail(Rejected, GB026LockTimerShape, call.Pos(), "%s.%s.%s must be inside `if st := %s.%s.Init(); st == 0 { … }` — without checking Init's status the timer is restarted on every run (Init returns -EBUSY after the first time)", l.checked.obj.Name(), fld.GoName, name, l.checked.obj.Name(), fld.GoName)
			return value{}, false, true
		}
	}
	if op == "timer_set_callback" {
		cb, ok := l.bindCallback(call.Args[0])
		if !ok {
			return value{}, false, true
		}
		l.emit("%s = ebpf.timer.set_callback %s %q, @%s : %s -> i64", r, b, fld.Name, cb.Symbol, bt)
		return value{r, i64}, true, true
	}
	ns, ok := l.expr(call.Args[0], &vtype{bits: 64})
	if !ok {
		return value{}, false, true
	}
	l.emit("%s = ebpf.timer.start %s %q, %s : %s, i64 -> i64", r, b, fld.Name, ns.name, bt)
	return value{r, i64}, true, true
}

// bindCallback checks the argument of SetCallback (a `func name(v *V)` in the same package) and binds the callback to the map (one callback, one map).
func (l *lowerer) bindCallback(e ast.Expr) (*TimerCallback, bool) {
	id, _ := ast.Unparen(e).(*ast.Ident)
	var fn *types.Func
	if id != nil {
		fn, _ = l.a.info.Uses[id].(*types.Func)
	}
	cb := l.a.timerCallbacks[fn]
	if fn == nil || cb == nil {
		l.fail(Rejected, GB026LockTimerShape, e.Pos(), "the callback of SetCallback must be a function of this package named directly, `func name(v *%s)`", l.checked.rec.Record.Symbol)
		return nil, false
	}
	pt, _ := cb.param.Type().(*types.Pointer)
	if pt == nil || !types.Identical(pt.Elem(), l.checked.rec.GoType) {
		l.fail(Rejected, GB026LockTimerShape, e.Pos(), "the callback %s must be `func %s(v *%s)` — the record of the timer's map %s", fn.Name(), fn.Name(), l.checked.rec.Record.Symbol, l.checked.m.Symbol)
		return nil, false
	}
	if cb.m != nil && cb.m != l.checked.m {
		l.fail(Rejected, GB026LockTimerShape, e.Pos(), "the callback %s is bound to map %s at %s — one callback serves one map (bpf-mlir's timer.callback names its map)", fn.Name(), cb.m.Symbol, posString(l.a.position(cb.mPos)))
		return nil, false
	}
	if cb.m == nil {
		cb.m, cb.mPos = l.checked.m, e.Pos()
	}
	return cb, true
}

// inInitGuard reports whether pos is in the then of an if where the status of ref's Timer Init is 0 (`if st := p.T.Init(); st == 0`,
// `if p.T.Init() == 0`, or `st := p.T.Init()` in an earlier statement tested by a later `if st == 0`; st must not be reassigned).
func (a *analyzer) inInitGuard(pos token.Pos, ref *types.Var) bool {
	for _, g := range a.initGuards {
		if g.ref == ref && g.then.Pos() <= pos && pos < g.then.End() {
			return true
		}
	}
	return false
}

type initGuard struct {
	ref  *types.Var
	then *ast.BlockStmt
}

// collectInitGuards collects the ifs on Init's status in a function body.
func (a *analyzer) collectInitGuards(body *ast.BlockStmt) {
	initRef := func(e ast.Expr) *types.Var { // p if e is `p.T.Init()`
		call, ok := ast.Unparen(e).(*ast.CallExpr)
		if !ok {
			return nil
		}
		sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
		if !ok {
			return nil
		}
		if o, ok := a.info.Uses[sel.Sel].(*types.Func); !ok || !inAPIPackage(o) {
			return nil
		} else if en, ok := lookupAPI(o); !ok || en.op != "timer_init" {
			return nil
		}
		inner, ok := ast.Unparen(sel.X).(*ast.SelectorExpr)
		if !ok {
			return nil
		}
		id, ok := inner.X.(*ast.Ident)
		if !ok {
			return nil
		}
		v, _ := a.info.Uses[id].(*types.Var)
		return v
	}
	statusDefs := map[*types.Var]*types.Var{} // st → p (`st := p.T.Init()`)
	assigned := map[*types.Var]int{}
	ast.Inspect(body, func(n ast.Node) bool {
		switch s := n.(type) {
		case *ast.AssignStmt:
			for _, lh := range s.Lhs {
				if id, ok := lh.(*ast.Ident); ok {
					if v, ok := a.info.Uses[id].(*types.Var); ok {
						assigned[v]++ // reassigned
					}
				}
			}
			if s.Tok == token.DEFINE && len(s.Lhs) == 1 && len(s.Rhs) == 1 {
				if id, ok := s.Lhs[0].(*ast.Ident); ok {
					if st, ok := a.info.Defs[id].(*types.Var); ok {
						if p := initRef(s.Rhs[0]); p != nil {
							statusDefs[st] = p
						}
					}
				}
			}
		case *ast.IncDecStmt:
			if id, ok := s.X.(*ast.Ident); ok {
				if v, ok := a.info.Uses[id].(*types.Var); ok {
					assigned[v]++
				}
			}
		}
		return true
	})
	isZero := func(e ast.Expr) bool {
		tv := a.info.Types[e]
		return tv.Value != nil && tv.Value.String() == "0"
	}
	ast.Inspect(body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		be, ok := ast.Unparen(is.Cond).(*ast.BinaryExpr)
		if !ok || be.Op != token.EQL {
			return true
		}
		side := be.X
		if isZero(be.X) {
			side = be.Y
		} else if !isZero(be.Y) {
			return true
		}
		if p := initRef(side); p != nil {
			a.initGuards = append(a.initGuards, initGuard{p, is.Body})
			return true
		}
		if id, ok := ast.Unparen(side).(*ast.Ident); ok {
			if st, ok := a.info.Uses[id].(*types.Var); ok && statusDefs[st] != nil && assigned[st] == 0 {
				a.initGuards = append(a.initGuards, initGuard{statusDefs[st], is.Body})
			}
		}
		return true
	})
}

// collectTimerCallbacks collects the functions passed to SetCallback (not made subprograms — after computeDomains, before collectSubprograms).
func (a *analyzer) collectTimerCallbacks() {
	decls := a.funcDecls()
	for _, fd := range decls {
		if fd.Body == nil {
			continue
		}
		a.collectInitGuards(fd.Body)
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) != 1 {
				return true
			}
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok {
				return true
			}
			o, ok := a.info.Uses[sel.Sel].(*types.Func)
			if !ok || !inAPIPackage(o) {
				return true
			}
			if en, ok := lookupAPI(o); !ok || en.op != "timer_set_callback" {
				return true
			}
			id, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
			if !ok {
				return true
			}
			fn, ok := a.info.Uses[id].(*types.Func)
			if !ok || fn.Pkg() != a.pkg.Types || a.timerCallbacks[fn] != nil {
				return true
			}
			cd := decls[fn]
			if cd == nil {
				return true
			}
			sig := fn.Type().(*types.Signature)
			cb := &TimerCallback{Symbol: fn.Name(), Pos: a.position(cd.Name.Pos()), decl: cd, obj: fn}
			if cd.Recv != nil || sig.TypeParams() != nil || sig.Params().Len() != 1 || sig.Results().Len() != 0 {
				a.report(Rejected, GB026LockTimerShape, cd.Name.Pos(), []string{fn.Name()}, "the timer callback %s must be `func %s(v *R)` — one pointer to the timer's record, no results", fn.Name(), fn.Name())
				return true
			}
			cb.param = sig.Params().At(0)
			a.timerCallbacks[fn] = cb
			return true
		})
	}
}

// lowerCallback lowers the body of a timer callback (after the programs — SetCallback binds the map).
func (a *analyzer) lowerCallback(cb *TimerCallback) {
	if cb.m == nil {
		return // already reported by the SetCallback check (an unbound callback is used outside a program)
	}
	pt := cb.param.Type().(*types.Pointer)
	rec := cb.m.Value
	if !types.Identical(pt.Elem(), rec.GoType) {
		return // bindCallback already reported it
	}
	l := &lowerer{a: a, name: cb.Symbol, b: &strings.Builder{}, indent: "  ", mapArgs: map[*BpfMap]string{}, env: map[*types.Var]value{}, bounds: map[string]uint64{}}
	l.fnBody = cb.decl.Body
	l.checkRMW(cb.decl, cb.param, cb.m) // the callback's RMW of its own value against the program's writes (rmw.go)
	l.callback = cb
	l.pushBorrow(&checkedRef{obj: cb.param, borrow: "%v", rec: &rec, m: cb.m})
	if !l.checkRegion(cb.decl.Body, cb.decl, "the timer callback "+cb.Symbol, true) {
		return
	}
	l.stmts(cb.decl.Body.List)
	func() {
		defer l.at(cb.decl.Body.Rbrace)()
		l.emit("ebpf.timer.done")
	}()
	if !l.failed {
		cb.body = l.b.String()
	}
}

// sortedCallbacks returns the callbacks in declaration position order (a deterministic order in the generated .mlir).
func (a *analyzer) sortedCallbacks() []*TimerCallback {
	var out []*TimerCallback
	for _, cb := range a.timerCallbacks {
		out = append(out, cb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].obj.Pos() < out[j].obj.Pos() })
	return out
}

// checkSpecialMaps limits maps whose value may hold a lock / timer record to bpf.Array (bpf-mlir's schema constraint, earlier).
func (a *analyzer) checkSpecialMaps() {
	for _, m := range a.maps {
		for _, s := range []struct {
			abi  *SharedABI
			role string
		}{{&m.Key, "key"}, {&m.Value, "value"}, {m.Event, "event"}} {
			if s.abi == nil || s.abi.Kind != ABIRecord || s.abi.Record.Special == nil {
				continue
			}
			if s.role == "value" && m.Kind == "array" {
				continue
			}
			sp := s.abi.Record.Special
			a.report(Rejected, GB026LockTimerShape, m.obj.Pos(), nil, "map %s: record %s holds %s %s — a record with a lock or a timer may only be the value of a bpf.Array (not the %s of a %s)", m.Symbol, s.abi.Record.Symbol, specialName(sp.Type.Kind), sp.GoName, s.role, m.Kind)
		}
	}
}

// checkSpecialMapUsers stops kprobe / uprobe programs from using a map with a lock / timer record (the kernel refuses it; fentry is accepted).
func (a *analyzer) checkSpecialMapUsers() {
	for _, p := range a.programs {
		if p.kind == nil || (p.kind.Kind != "kprobe" && p.kind.Kind != "uprobe") {
			continue
		}
		c := a.closures[p]
		if c == nil {
			continue
		}
		for _, m := range c.Maps {
			if m.Value.Kind == ABIRecord && m.Value.Record.Special != nil {
				a.report(Rejected, GB026LockTimerShape, p.decl.Name.Pos(), []string{p.Symbol}, "the %s program %s uses map %s, whose value %s holds %s — the kernel refuses a map with a spin lock or a timer in %s programs (use fentry, or keep the lock / timer in a map this program does not touch)", p.kind.Kind, p.Symbol, m.Symbol, m.Value.Record.Symbol, specialName(m.Value.Record.Special.Type.Kind), p.kind.Kind)
			}
		}
	}
}
