package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// User ring buffers (bpf-mlir's user_ringbuf map and ebpf.user_ringbuf.drain / callback / done).
//
//	var In = bpf.UserRingBuf[Req]{MaxEntries: 4096}
//	n := In.Drain(onReq)                → %n = ebpf.user_ringbuf.drain "In", @onReq -> i64
//	func onReq(r Req, ok bool) bool {…}  → ebpf.user_ringbuf.callback @onReq { ^bb0(%d: !ebpf.dynptr<"user_ringbuf">):
//	                                         %f0, %s0 = ebpf.dynptr.read %d[off0] … (every field of V — once at entry), ok = every %s == 0, the body,
//	                                         ebpf.user_ringbuf.done stop %c }
//
// Per bpf-mlir's constraints the callback body has only arithmetic, Add / Load of bpf.Global, KtimeNs and if (map, helper and loop stop — GB026), and return is
// only the last statement of the body. Drain only in a program body (stops in a subprogram, loop or callback).

// UrbCallback is a drain callback function (the argument of Drain).
type UrbCallback struct {
	Symbol string
	Pos    token.Position
	decl   *ast.FuncDecl
	obj    *types.Func
	rParam *types.Var
	okVar  *types.Var
	m      *BpfMap // the bound map (the receiver of the first Drain)
	body   string
	bad    bool // a signature error (already reported — not made a subprogram either)
}

// userRingBufInstance returns V if t is an instance of bpf.UserRingBuf[V].
func userRingBufInstance(t types.Type) (types.Type, bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg || n.Origin().Obj().Name() != "UserRingBuf" {
		return nil, false
	}
	args := n.TypeArgs()
	if args == nil || args.Len() != 1 {
		return nil, false
	}
	return args.At(0), true
}

// collectUserRingBuf checks and collects user ring buffer declarations (the sample is a record — the same rule as ring buffers, and the ring must fit one sample).
func (a *analyzer) collectUserRingBuf(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, v types.Type) {
	m := &BpfMap{Symbol: obj.Name(), Kind: "user_ringbuf", Pos: a.position(name.Pos()), obj: obj}
	if _, isStruct := v.Underlying().(*types.Struct); !isStruct {
		a.report(Rejected, GB016SharedABIShape, name.Pos(), nil, "user ring buffer %s: the sample type must be a record (a named struct type declared in this package), got %s", obj.Name(), a.typeString(v))
		return
	}
	rv, ok := a.recordOf(v, name.Pos(), "user ring buffer "+obj.Name()+" sample")
	if !ok {
		return
	}
	for _, f := range rv.Record.Fields {
		if f.Type.Kind != ABIInt {
			a.report(Rejected, GB016SharedABIShape, name.Pos(), nil, "user ring buffer %s: field %s of the sample %s must be an integer (the drain callback reads integer fields — bpf-mlir ebpf.dynptr.read)", obj.Name(), f.GoName, a.typeString(v))
			return
		}
	}
	m.Value = rv
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "user ring buffer %s needs an initializer bpf.UserRingBuf[V]{MaxEntries: N} (MaxEntries is required)", obj.Name())
		return
	}
	if !a.mapInit(m, vs.Values[i]) {
		return
	}
	if n := m.MaxEntries; n < ringbufMinBytes || n&(n-1) != 0 {
		a.report(Rejected, GB009MapDeclShape, m.maxPos, nil, "user ring buffer %s: MaxEntries (bytes) must be a power of two and a multiple of the x86_64 page size (4096), got %d", obj.Name(), n)
		return
	}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// collectUrbCallbacks collects the functions passed to Drain (not made subprograms — at the same time as timer callbacks).
func (a *analyzer) collectUrbCallbacks() {
	decls := a.funcDecls()
	for _, fd := range decls {
		if fd.Body == nil {
			continue
		}
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
			if en, ok := lookupAPI(o); !ok || en.op != "urb_drain" {
				return true
			}
			id, ok := ast.Unparen(call.Args[0]).(*ast.Ident)
			if !ok {
				return true
			}
			fn, ok := a.info.Uses[id].(*types.Func)
			if !ok || fn.Pkg() != a.pkg.Types || a.urbCallbacks[fn] != nil {
				return true
			}
			cd := decls[fn]
			if cd == nil {
				return true
			}
			sig := fn.Type().(*types.Signature)
			cb := &UrbCallback{Symbol: fn.Name(), Pos: a.position(cd.Name.Pos()), decl: cd, obj: fn}
			if cd.Recv != nil || sig.TypeParams() != nil || sig.Params().Len() != 2 || sig.Results().Len() != 1 || !isBoolType(sig.Params().At(1).Type()) || !isBoolType(sig.Results().At(0).Type()) {
				a.report(Rejected, GB026LockTimerShape, cd.Name.Pos(), []string{fn.Name()}, "the drain callback %s must be `func %s(r V, ok bool) bool` — the sample (the user ring buffer's record), whether it covers the record, and true to stop", fn.Name(), fn.Name())
				cb.bad = true
				a.urbCallbacks[fn] = cb
				return true
			}
			cb.rParam, cb.okVar = sig.Params().At(0), sig.Params().At(1)
			a.urbCallbacks[fn] = cb
			return true
		})
	}
}

func isBoolType(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

// urbDrain lowers `M.Drain(cb)` to ebpf.user_ringbuf.drain. handled reports whether e is that call.
func (l *lowerer) urbDrain(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "urb_drain" {
		return value{}, false, false
	}
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	var m *BpfMap
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); ok {
		if v, ok := l.a.info.Uses[id].(*types.Var); ok {
			m = l.a.mapByObj[v]
		}
	}
	if m == nil || m.Kind != "user_ringbuf" {
		l.fail(Rejected, GB009MapDeclShape, e.Pos(), "Drain must be called on a package-level bpf.UserRingBuf variable")
		return value{}, false, true
	}
	switch {
	case l.urbCB != nil:
		l.fail(Rejected, GB026LockTimerShape, e.Pos(), "%s.Drain cannot be called inside a drain callback", m.Symbol)
		return value{}, false, true
	case l.prog == nil:
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "%s.Drain may only be called in a program body (bpf-mlir ebpf.user_ringbuf.drain — not in a subprogram)", m.Symbol)
		return value{}, false, true
	case len(l.loops) > 0:
		l.fail(Rejected, GB018LoopShape, e.Pos(), "%s.Drain cannot be called inside a loop (bpf-mlir does not allow ebpf.user_ringbuf.drain in a loop body) — call it before the loop", m.Symbol)
		return value{}, false, true
	}
	id, _ := ast.Unparen(e.Args[0]).(*ast.Ident)
	var cb *UrbCallback
	if id != nil {
		if fn, ok := l.a.info.Uses[id].(*types.Func); ok {
			cb = l.a.urbCallbacks[fn]
		}
	}
	if cb == nil {
		l.fail(Rejected, GB026LockTimerShape, e.Args[0].Pos(), "the argument of %s.Drain must be a package function `func name(r V, ok bool) bool` (the drain callback)", m.Symbol)
		return value{}, false, true
	}
	if cb.bad {
		l.failed = true // collectUrbCallbacks already reported the signature error
		return value{}, false, true
	}
	if !types.Identical(cb.rParam.Type(), m.Value.GoType) {
		l.fail(Rejected, GB026LockTimerShape, e.Args[0].Pos(), "the drain callback %s takes %s, but %s holds %s", cb.Symbol, l.a.typeString(cb.rParam.Type()), m.Symbol, l.a.typeString(m.Value.GoType))
		return value{}, false, true
	}
	if cb.m == nil {
		cb.m = m
	} else if cb.m != m {
		l.fail(Rejected, GB026LockTimerShape, e.Args[0].Pos(), "the drain callback %s is already used with %s — one callback drains one user ring buffer", cb.Symbol, cb.m.Symbol)
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.user_ringbuf.drain %q, @%s -> i64", r, m.Symbol, cb.Symbol)
	return value{r, vtype{bits: 64, signed: true}}, true, true
}

// urbPure reports whether e may be evaluated without branches (identifiers, constants, type conversions, unary − + ^, binary + − * & | ^, comparisons, && / || (with no call on the right),
// calls of bpf.Global's Load and KtimeNs) — a drain callback cannot branch under bpf-mlir's constraints (ebpf.if is refused inside a callback).
func (l *lowerer) urbPure(e ast.Expr) (ast.Node, bool) {
	var bad ast.Node
	ast.Inspect(e, func(n ast.Node) bool {
		if bad != nil {
			return false
		}
		switch x := n.(type) {
		case nil, *ast.Ident, *ast.BasicLit, *ast.ParenExpr, *ast.SelectorExpr:
		case *ast.UnaryExpr:
			if x.Op != token.SUB && x.Op != token.ADD && x.Op != token.XOR && x.Op != token.NOT {
				bad = x
			}
		case *ast.BinaryExpr:
			switch x.Op {
			case token.ADD, token.SUB, token.MUL, token.AND, token.OR, token.XOR, token.EQL, token.NEQ, token.LSS, token.LEQ, token.GTR, token.GEQ:
			case token.LAND, token.LOR:
				hasCall := false
				ast.Inspect(x.Y, func(m ast.Node) bool {
					if c, ok := m.(*ast.CallExpr); ok && !l.a.info.Types[c.Fun].IsType() {
						hasCall = true
					}
					return !hasCall
				})
				if hasCall {
					bad = x
				}
			default:
				bad = x
			}
		case *ast.CallExpr:
			if l.a.info.Types[x.Fun].IsType() {
				return true
			}
			if op := l.callOp(x); op != "global_load" && op != "ktime" {
				bad = x
			}
		default:
			bad = x
		}
		return true
	})
	return bad, bad == nil
}

// urbAddCall returns the call if statement s is `G.Add(x)` (Add of bpf.Global).
func (l *lowerer) urbAddCall(s ast.Stmt) (*ast.CallExpr, bool) {
	es, ok := s.(*ast.ExprStmt)
	if !ok {
		return nil, false
	}
	call, ok := ast.Unparen(es.X).(*ast.CallExpr)
	if !ok || l.callOp(call) != "global_add" {
		return nil, false
	}
	return call, true
}

// urbCheckBody checks the shape of a drain callback body (bpf-mlir's callback cannot branch): top-level statements are assignments, declarations, `G.Add(x)` and if (whose then / else
// statements are only `G.Add(x)` — lowered to a branchless select), expressions may be evaluated without branches (urbPure), and return is the last statement.
func (l *lowerer) urbCheckBody(cb *UrbCallback) bool {
	good := true
	list := cb.decl.Body.List
	failIf := func(n ast.Node, what string) {
		if good {
			l.fail(Rejected, GB026LockTimerShape, n.Pos(), "the drain callback %s: %s — the callback has no branches (bpf-mlir ebpf.user_ringbuf.callback allows only arithmetic, the sample reads, bpf.Global Add / Load and bpf.KtimeNs); an `if` may only wrap bpf.Global Add calls (lowered without branches)", cb.Symbol, what)
		}
		good = false
	}
	for _, s := range list {
		switch x := s.(type) {
		case *ast.IfStmt:
			if x.Init != nil {
				failIf(x, "an if with an init statement")
				continue
			}
			if n, ok := l.urbPure(x.Cond); !ok {
				failIf(n, "this condition needs a branch")
				continue
			}
			arms := []*ast.BlockStmt{x.Body}
			if x.Else != nil {
				eb, ok := x.Else.(*ast.BlockStmt)
				if !ok {
					failIf(x.Else, "an else-if")
					continue
				}
				arms = append(arms, eb)
			}
			for _, arm := range arms {
				for _, as := range arm.List {
					call, ok := l.urbAddCall(as)
					if !ok {
						failIf(as, "only bpf.Global Add calls may be inside an if")
						continue
					}
					if n, ok := l.urbPure(call.Args[0]); !ok {
						failIf(n, "this value needs a branch")
					}
				}
			}
		case *ast.ReturnStmt:
			for _, r := range x.Results {
				if n, ok := l.urbPure(r); !ok {
					failIf(n, "this result needs a branch")
				}
			}
		case *ast.AssignStmt:
			for _, r := range x.Rhs {
				if n, ok := l.urbPure(r); !ok {
					failIf(n, "this value needs a branch")
				}
			}
		case *ast.ExprStmt:
			if call, ok := l.urbAddCall(x); ok {
				if n, ok := l.urbPure(call.Args[0]); !ok {
					failIf(n, "this value needs a branch")
				}
				continue
			}
			failIf(x, "only bpf.Global Add calls may be statements")
		case *ast.DeclStmt:
		default:
			failIf(x, "this statement")
		}
	}
	if !good {
		return false
	}
	if len(list) == 0 {
		l.fail(Rejected, GB026LockTimerShape, cb.decl.Body.Rbrace, "the drain callback %s must end with `return <bool>`", cb.Symbol)
		return false
	}
	if _, ok := list[len(list)-1].(*ast.ReturnStmt); !ok {
		l.fail(Rejected, GB026LockTimerShape, list[len(list)-1].Pos(), "the drain callback %s must end with `return <bool>` (true stops the drain)", cb.Symbol)
		return false
	}
	ast.Inspect(cb.decl.Body, func(n ast.Node) bool {
		if !good {
			return false
		}
		switch x := n.(type) {
		case *ast.ReturnStmt:
			if x != list[len(list)-1] {
				l.fail(Rejected, GB026LockTimerShape, x.Pos(), "the drain callback %s may return only at its end (`return <bool>` as the last statement)", cb.Symbol)
				good = false
			}
		case *ast.ForStmt, *ast.RangeStmt, *ast.GoStmt, *ast.DeferStmt, *ast.FuncLit, *ast.SwitchStmt, *ast.TypeSwitchStmt, *ast.SelectStmt, *ast.BranchStmt:
			l.fail(Rejected, GB026LockTimerShape, x.Pos(), "the drain callback %s may use only arithmetic, if, bpf.Global Add / Load and bpf.KtimeNs (bpf-mlir ebpf.user_ringbuf.callback)", cb.Symbol)
			good = false
		case *ast.CallExpr:
			if tv := l.a.info.Types[x.Fun]; tv.IsType() {
				return true
			}
			switch op := l.callOp(x); op {
			case "global_add", "global_load", "ktime":
			default:
				l.fail(Rejected, GB026LockTimerShape, x.Pos(), "the drain callback %s cannot call %s — it may use only arithmetic, if, bpf.Global Add / Load and bpf.KtimeNs (bpf-mlir ebpf.user_ringbuf.callback — no map, no helper)", cb.Symbol, types.ExprString(x.Fun))
				good = false
			}
		}
		return true
	})
	return good
}

// urbField lowers `r.F` in a callback to the value read at entry. handled reports whether e reads a field of the callback's sample (other uses of r stop).
func (l *lowerer) urbField(e ast.Expr) (value, bool, bool) {
	if l.urbCB == nil {
		return value{}, false, false
	}
	switch x := ast.Unparen(e).(type) {
	case *ast.SelectorExpr:
		id, ok := ast.Unparen(x.X).(*ast.Ident)
		if !ok || l.a.info.Uses[id] != types.Object(l.urbCB.rParam) {
			return value{}, false, false
		}
		v, ok := l.urbFields[x.Sel.Name]
		if !ok {
			l.fail(Rejected, GB026LockTimerShape, x.Pos(), "%s is not an integer field of the sample", types.ExprString(x))
			return value{}, false, true
		}
		return v, true, true
	case *ast.Ident:
		if l.a.info.Uses[x] == types.Object(l.urbCB.rParam) {
			l.fail(Rejected, GB026LockTimerShape, x.Pos(), "the sample %s may be used only through its fields (%s.F) in the drain callback", x.Name, x.Name)
			return value{}, false, true
		}
	}
	return value{}, false, false
}

// lowerUrbCallback lowers the body of a drain callback (after the programs — Drain binds the map).
func (a *analyzer) lowerUrbCallback(cb *UrbCallback) {
	if cb.m == nil || cb.bad {
		return // already reported by the Drain or signature check, or used outside a program
	}
	l := &lowerer{a: a, name: cb.Symbol, b: &strings.Builder{}, indent: "  ", mapArgs: map[*BpfMap]string{}, env: map[*types.Var]value{}, bounds: map[string]uint64{}}
	l.fnBody = cb.decl.Body
	l.urbCB = cb
	l.urbFields = map[string]value{}
	if !l.urbCheckBody(cb) {
		return
	}
	defer l.at(cb.decl.Name.Pos())()
	var oks []string
	for _, f := range cb.m.Value.Record.Fields {
		o, v, st := l.val(), l.val(), l.val()
		it := *f.Type.Int
		l.emit("%s = arith.constant %d : i32", o, f.Offset)
		l.emit("%s, %s = ebpf.dynptr.read %%d[%s] : !ebpf.dynptr<\"user_ringbuf\"> -> %s, i64", v, st, o, it.mlir())
		l.urbFields[f.GoName] = value{v, vtypeOf(it)}
		z, c := l.val(), l.val()
		l.emit("%s = arith.constant 0 : i64", z)
		l.emit("%s = arith.cmpi eq, %s, %s : i64", c, st, z)
		oks = append(oks, c)
	}
	ok := oks[0]
	for _, c := range oks[1:] {
		r := l.val()
		l.emit("%s = arith.andi %s, %s : i1", r, ok, c)
		ok = r
	}
	l.env[cb.okVar] = value{ok, vtype{isBool: true}}
	list := cb.decl.Body.List
	for _, s := range list[:len(list)-1] {
		is, ok := s.(*ast.IfStmt)
		if !ok {
			l.stmts([]ast.Stmt{s})
			continue
		}
		// if without branches: `G.Add(x)` in then becomes `G.Add(select(c, x, 0))`, in else `G.Add(select(c, 0, x))` (an atomic_add of 0 does not change the value).
		bt := vtype{isBool: true}
		c, okc := l.expr(is.Cond, &bt)
		if !okc {
			return
		}
		arms := []struct {
			list []ast.Stmt
			then bool
		}{{is.Body.List, true}}
		if eb, ok := is.Else.(*ast.BlockStmt); ok {
			arms = append(arms, struct {
				list []ast.Stmt
				then bool
			}{eb.List, false})
		}
		for _, arm := range arms {
			for _, as := range arm.list {
				call, _ := l.urbAddCall(as)
				if !l.urbPredAdd(call, c, arm.then) {
					return
				}
			}
		}
	}
	ret := list[len(list)-1].(*ast.ReturnStmt)
	if len(ret.Results) != 1 {
		l.fail(Rejected, GB026LockTimerShape, ret.Pos(), "the drain callback %s must return one bool", cb.Symbol)
		return
	}
	bt := vtype{isBool: true}
	c, okv := l.expr(ret.Results[0], &bt)
	if !okv {
		return
	}
	func() {
		defer l.at(ret.Pos())()
		l.emit("ebpf.user_ringbuf.done stop %s", c.name)
	}()
	if !l.failed {
		cb.body = l.b.String()
	}
}

// urbPredAdd lowers `G.Add(x)` to the branchless shape `G.Add(select(c, x, 0))` that takes effect only on the branch of c (for then, when c is true).
func (l *lowerer) urbPredAdd(call *ast.CallExpr, c value, then bool) bool {
	sel := call.Fun.(*ast.SelectorExpr)
	recv, _ := sel.X.(*ast.Ident)
	v, _ := l.a.info.Uses[recv].(*types.Var)
	g := l.a.globalByObj[v]
	if g == nil {
		l.fail(Rejected, GB026LockTimerShape, call.Pos(), "%s is not a bpf.Global", types.ExprString(sel.X))
		return false
	}
	defer l.at(call.Pos())()
	t := vtypeOf(g.Int)
	d, ok := l.expr(call.Args[0], &t)
	if !ok {
		return false
	}
	z, r := l.val(), l.val()
	l.emit("%s = arith.constant 0 : %s", z, t.mlir())
	a, b := d.name, z
	if !then {
		a, b = z, d.name
	}
	l.emit("%s = arith.select %s, %s, %s : %s", r, c.name, a, b, t.mlir())
	l.emit("ebpf.global.atomic_add @%s, %s : %s", g.Symbol, r, t.mlir())
	return true
}

// sortedUrbCallbacks returns the drain callbacks in declaration position order (a deterministic order in the generated .mlir).
func (a *analyzer) sortedUrbCallbacks() []*UrbCallback {
	var out []*UrbCallback
	for _, cb := range a.urbCallbacks {
		out = append(out, cb)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].obj.Pos() < out[j].obj.Pos() })
	return out
}

// emitUrbCallbacks returns the text of the module's top-level ebpf.user_ringbuf.callback ops.
func emitUrbCallbacks(cbs []*UrbCallback) string {
	var b strings.Builder
	for _, cb := range cbs {
		if cb.m == nil {
			continue
		}
		fmt.Fprintf(&b, "ebpf.user_ringbuf.callback @%s {\n^bb0(%%d: !ebpf.dynptr<\"user_ringbuf\">):\n%s}%s\n\n", cb.Symbol, cb.body, locText(cb.Pos))
	}
	return b.String()
}
