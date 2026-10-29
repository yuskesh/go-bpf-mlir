package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// map-in-map (bpf-mlir's array_of_maps / hash_of_maps):
//
//	var AOM = bpf.ArrayOfMaps[uint32, uint64]{MaxEntries: 3, Inner: bpf.InnerSpec{Kind: bpf.InnerHash, MaxEntries: 4}}
//	if m := AOM.Lookup(k); m != nil {      → %r = ebpf.map.lookup %AOM[%k] : !ebpf.map<"array_of_maps", i32, !ebpf.map<"hash", i32, i64>>, i32 -> !ebpf.maybe_ref<!ebpf.map<"hash", i32, i64>>
//		…                                    ebpf.ref.check %r present(%b: !ebpf.borrowed<!ebpf.map<…>>) { %in = ebpf.map.inner %b : … -> !ebpf.map<"hash", i32, i64>; … } absent { … }
//		m.AtomicAdd(1, 1)                  → ebpf.map.atomic_add %in[…]
//	}
//
// The inner template is the schema map `<outer>_inner` (the outer map's `inner`) — not in the program's maps, the ELF's .maps or a.maps (BpfMap.InnerTpl). The inner handle m
// can be used only as the receiver of `m.Lookup / Update / AtomicAdd(…)` inside the checked branch (bpf-mlir's map.inner constraint — never outside the branch, in a loop body, or in a yield / call).

// innerKinds maps a bpf.InnerKind value to the schema kind.
var innerKinds = map[uint64]string{1: "array", 2: "hash", 3: "lru_hash"}

// mapInMapInstance returns the kind, the outer key and the inner K / V if t is an instance of bpf.ArrayOfMaps / HashOfMaps.
func mapInMapInstance(t types.Type) (kind string, ok types.Type, k, v types.Type, isMIM bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg {
		return "", nil, nil, nil, false
	}
	switch n.Origin().Obj().Name() {
	case "ArrayOfMaps":
		if n.TypeArgs().Len() == 2 {
			return "array_of_maps", types.Typ[types.Uint32], n.TypeArgs().At(0), n.TypeArgs().At(1), true
		}
	case "HashOfMaps":
		if n.TypeArgs().Len() == 3 {
			return "hash_of_maps", n.TypeArgs().At(0), n.TypeArgs().At(1), n.TypeArgs().At(2), true
		}
	}
	return "", nil, nil, nil, false
}

// collectMapInMap collects the outer map and the inner template (`{MaxEntries: N, Inner: bpf.InnerSpec{Kind: bpf.InnerHash, MaxEntries: M}}`).
func (a *analyzer) collectMapInMap(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, kind string, okT, kT, vT types.Type) {
	u32 := types.Typ[types.Uint32]
	oki, _ := intTypeOf(okT)
	ki, _ := intTypeOf(kT)
	vi, _ := intTypeOf(vT)
	if vi.Bits < 32 {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s: the inner value must be a 32 or 64 bit integer, got %s", obj.Name(), a.typeString(vT))
		return
	}
	outer := &BpfMap{Symbol: obj.Name(), Kind: kind, Pos: a.position(name.Pos()), obj: obj,
		Key: sharedABIOfInt(okT, oki), Value: sharedABIOfInt(u32, IntType{32, false})}
	tpl := &BpfMap{Symbol: obj.Name() + "_inner", Pos: outer.Pos, Key: sharedABIOfInt(kT, ki), Value: sharedABIOfInt(vT, vi)}
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s needs an initializer with MaxEntries and Inner (bpf.InnerSpec{Kind: …, MaxEntries: …})", obj.Name())
		return
	}
	cl, isCL := vs.Values[i].(*ast.CompositeLit)
	if !isCL {
		a.report(Rejected, GB009MapDeclShape, vs.Values[i].Pos(), nil, "map %s: the initializer must be a composite literal with MaxEntries and Inner", obj.Name())
		return
	}
	var rest []ast.Expr
	var inner *ast.CompositeLit
	for _, el := range cl.Elts {
		kv, isKV := el.(*ast.KeyValueExpr)
		key, _ := kv.Key.(*ast.Ident)
		if isKV && key != nil && key.Name == "Inner" {
			inner, _ = kv.Value.(*ast.CompositeLit)
			if inner == nil {
				a.report(Rejected, GB009MapDeclShape, kv.Value.Pos(), nil, "map %s: Inner must be a composite literal bpf.InnerSpec{Kind: …, MaxEntries: …}", obj.Name())
				return
			}
			continue
		}
		rest = append(rest, el)
	}
	if inner == nil {
		a.report(Rejected, GB009MapDeclShape, cl.Pos(), nil, "map %s: Inner is required (the inner map template — bpf.InnerSpec{Kind: bpf.InnerHash, MaxEntries: N})", obj.Name())
		return
	}
	lit := *cl
	lit.Elts = rest
	if !a.mapInit(outer, &lit) {
		return
	}
	var innerRest []ast.Expr
	for _, el := range inner.Elts {
		kv, isKV := el.(*ast.KeyValueExpr)
		key, _ := kv.Key.(*ast.Ident)
		if isKV && key != nil && key.Name == "Kind" {
			tv := a.info.Types[kv.Value]
			n, exact := uint64(0), false
			if tv.Value != nil {
				n, exact = constUint64(tv)
			}
			if tv.Value == nil || !exact || innerKinds[n] == "" {
				a.report(Rejected, GB006NonConstant, kv.Value.Pos(), nil, "map %s: Inner.Kind must be the constant bpf.InnerArray, bpf.InnerHash or bpf.InnerLRUHash", obj.Name())
				return
			}
			tpl.Kind = innerKinds[n]
			continue
		}
		innerRest = append(innerRest, el)
	}
	if tpl.Kind == "" {
		a.report(Rejected, GB009MapDeclShape, inner.Pos(), nil, "map %s: Inner.Kind is required (bpf.InnerArray, bpf.InnerHash or bpf.InnerLRUHash)", obj.Name())
		return
	}
	ilit := *inner
	ilit.Elts = innerRest
	if !a.mapInit(tpl, &ilit) {
		return
	}
	outer.InnerTpl = tpl
	a.maps = append(a.maps, outer)
	a.mapByObj[obj] = outer
}

// outerLookupCall returns the outer map if call is the outer Lookup of a map-in-map.
func (l *lowerer) outerLookupCall(e ast.Expr) (*ast.CallExpr, *BpfMap, bool) {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, nil, false
	}
	m, en, _, known := l.mapMethod(call)
	if m == nil || !known || en.op != "outer_lookup" {
		return nil, nil, false
	}
	return call, m, true
}

// isOuterLookupIf reports whether s is `if m := Outer.Lookup(k); …`.
func (l *lowerer) isOuterLookupIf(s *ast.IfStmt) bool {
	as, ok := s.Init.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return false
	}
	_, _, isOuter := l.outerLookupCall(as.Rhs[0])
	return isOuter
}

// bindInnerHandles binds the m of `if m := Outer.Lookup(k); …` in the body to the inner template (before lowering and the RMW check — mapMethod / mapOfExpr look it up).
func (a *analyzer) bindInnerHandles(body ast.Node) {
	ast.Inspect(body, func(n ast.Node) bool {
		s, ok := n.(*ast.IfStmt)
		if !ok {
			return true
		}
		as, ok := s.Init.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || as.Tok != token.DEFINE {
			return true
		}
		call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Lookup" {
			return true
		}
		recv, ok := sel.X.(*ast.Ident)
		if !ok {
			return true
		}
		rv, _ := a.info.Uses[recv].(*types.Var)
		outer := a.mapByObj[rv]
		id, _ := as.Lhs[0].(*ast.Ident)
		if outer == nil || outer.InnerTpl == nil || id == nil {
			return true
		}
		if mv, _ := a.info.Defs[id].(*types.Var); mv != nil {
			a.innerByVar[mv] = outer.InnerTpl
		}
		return true
	})
}

// ifOuterLookup lowers `if m := Outer.Lookup(k); m != nil { … } [else { … }]` in two steps: the outer map.lookup and ref.check, then map.inner.
func (l *lowerer) ifOuterLookup(s *ast.IfStmt) {
	as := s.Init.(*ast.AssignStmt)
	call, outer, _ := l.outerLookupCall(as.Rhs[0])
	tpl := outer.InnerTpl
	shape := func(p token.Pos, what string) {
		l.fail(Rejected, GB005NilCheckShape, p, "%s — the supported form is `if m := %s.Lookup(k); m != nil { … m.Lookup / m.Update / m.AtomicAdd … } [else { … }]`", what, outer.Symbol)
	}
	mid, _ := as.Lhs[0].(*ast.Ident)
	if as.Tok != token.DEFINE || len(as.Lhs) != 1 || mid == nil || mid.Name == "_" {
		shape(as.Pos(), "the if statement's init must declare one variable")
		return
	}
	mobj, _ := l.a.info.Defs[mid].(*types.Var)
	if !l.isNilCheck(s.Cond, mobj) {
		shape(s.Cond.Pos(), fmt.Sprintf("the condition must be exactly `%s != nil`", mid.Name))
		return
	}
	var elseBlock *ast.BlockStmt
	if s.Else != nil {
		eb, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			shape(s.Else.Pos(), "else-if is not supported")
			return
		}
		elseBlock = eb
		l.rejectUses(eb, mobj, "the inner map is absent in the else branch")
		if l.failed {
			return
		}
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "%s.Lookup cannot be checked inside a loop (bpf-mlir keeps the inner map handle out of loop bodies) — check it before the loop", outer.Symbol)
		return
	}
	if !l.checkInnerUses(s.Body, mobj, outer) {
		return
	}
	defer l.at(s.Pos())()
	k, ok := l.mapKey(outer, call.Args[0])
	if !ok {
		return
	}
	it := mapTypeOf(tpl)
	ref := l.val()
	l.emit("%s = ebpf.map.lookup %s[%s] : %s, %s -> !ebpf.maybe_ref<%s>", ref, l.mapArgs[outer], k, l.mapType(outer), outer.Key.mlir(), it)
	borrow, in := l.val(), l.val()
	before := copyEnv(l.env)
	l.env = copyEnv(before)
	l.escaped = false
	l.mapArgs[tpl] = in
	presentText := l.region(func() {
		l.emit("%s = ebpf.map.inner %s : !ebpf.borrowed<%s> -> %s", in, borrow, it, it)
		l.stmts(s.Body.List)
	})
	delete(l.mapArgs, tpl)
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
	l.b.WriteString(fmt.Sprintf("%s%sebpf.ref.check %s : !ebpf.maybe_ref<%s>%s present {\n%s^present(%s: !ebpf.borrowed<%s>):\n%s%s} absent {\n%s%s}%s\n",
		l.indent, head, ref, it, typeList, l.indent, borrow, it, presentText, l.indent, absentText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(mods, before, base)
	}
}

// checkInnerUses checks that every use of the inner handle m is the receiver of `m.Lookup / m.Update / m.AtomicAdd(…)` and is not inside a loop body (GB005 / GB018).
func (l *lowerer) checkInnerUses(body *ast.BlockStmt, mobj *types.Var, outer *BpfMap) bool {
	good := true
	walkWithStack(body, func(n ast.Node, stack []ast.Node) {
		id, ok := n.(*ast.Ident)
		if !ok || l.a.info.Uses[id] != mobj {
			return
		}
		for _, p := range stack {
			switch p.(type) {
			case *ast.ForStmt, *ast.RangeStmt:
				l.fail(Rejected, GB018LoopShape, id.Pos(), "the inner map %s of %s cannot be used inside a loop (bpf-mlir keeps the inner map handle out of loop bodies) — read what you need before the loop", id.Name, outer.Symbol)
				good = false
				return
			case *ast.FuncLit:
				l.fail(Rejected, GB005NilCheckShape, id.Pos(), "the inner map %s cannot be captured by a function literal", id.Name)
				good = false
				return
			}
		}
		sel, isSel := parent(stack, 1).(*ast.SelectorExpr)
		call, isCall := parent(stack, 2).(*ast.CallExpr)
		if !isSel || sel.X != ast.Expr(id) || !isCall || call.Fun != ast.Expr(sel) {
			l.fail(Rejected, GB005NilCheckShape, id.Pos(), "the inner map %s of %s may only be used as the receiver of %s.Lookup / %s.Update / %s.AtomicAdd (it cannot be stored, compared, passed to a function or leave the checked branch)", id.Name, outer.Symbol, id.Name, id.Name, id.Name)
			good = false
		}
	})
	return good
}
