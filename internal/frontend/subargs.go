package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// Map value borrow arguments of subprograms, and global subprograms (shapes (A) / (B)). bpf-mlir's ebpf.func
// takes integers, or `!ebpf.maybe_ref<T>` (unchecked) / `!ebpf.borrowed<T>` (checked) pointing at an integer or record, as arguments (writable too), and its linkage is
// static / global (a borrowed argument of a global function is arg:nonnull — the argtag requirement; the target check stops it on 6.6.157).
//
//	(A) the caller passes a checked borrow: `if p := M.Lookup(k); p != nil { f(p) }` → the callee argument is borrowed (readable without a check)
//	(B) the caller passes an unchecked Lookup result directly: `f(M.Lookup(k))` → maybe_ref (the callee reads only inside an `if p != nil { … }` branch)
//
// The argument shape is decided by **the set of all call sites** of the same callee, and if both shapes are mixed GB013 names every site.
// A callee can write through a borrow (a non-atomic RMW of a shared map value is GB028 / GB021 at the call site — rmw.go). A subprogram marked `//gobpf:global` is "global".

// collectGlobalDirectives collects `//gobpf:global` (before checkStrayDirectives — a doc mark). The mark on a program function is GB013.
func (a *analyzer) collectGlobalDirectives() {
	a.globalFuncs = map[*types.Func]token.Pos{}
	progs := map[*types.Func]bool{}
	for _, p := range a.programs {
		progs[p.obj] = true
	}
	for fn, fd := range a.funcDecls() {
		if fd.Doc == nil {
			continue
		}
		var at token.Pos
		other := false
		for _, c := range fd.Doc.List {
			m := directiveRE.FindStringSubmatch(c.Text)
			if m == nil {
				continue
			}
			if m[1] != "global" {
				other = true
				continue
			}
			at = c.Pos()
			if strings.TrimSpace(m[2]) != "" {
				a.report(Rejected, GB013SubprogramShape, c.Pos(), []string{fd.Name.Name}, "//gobpf:global takes no arguments (got %q)", strings.TrimSpace(m[2]))
			}
		}
		if at == token.NoPos {
			continue
		}
		if progs[fn] {
			a.report(Rejected, GB013SubprogramShape, at, []string{fd.Name.Name}, "//gobpf:global marks a subprogram (a helper called from a program) — %s is a program; remove the directive", fd.Name.Name)
		} else {
			a.globalFuncs[fn] = at
		}
		if !other {
			a.directiveOf[fd.Doc] = true
		}
	}
}

// mapValuePointee returns the ABI of the type if t is a pointer to a map value type (an integer or record — excluding lock / timer records).
func (a *analyzer) mapValuePointee(t types.Type) (SharedABI, bool) {
	p, ok := t.(*types.Pointer)
	if !ok {
		return SharedABI{}, false
	}
	for _, m := range a.maps {
		switch m.Kind {
		case "array", "percpu_array", "hash", "lru_hash", "percpu_hash", "lru_percpu_hash":
		default:
			continue
		}
		v := m.Value
		if v.GoType == nil || !types.Identical(v.GoType, p.Elem()) {
			continue
		}
		if v.Kind == ABIInt || (v.Kind == ABIRecord && (v.Record == nil || v.Record.Special == nil)) {
			return v, true
		}
	}
	return SharedABI{}, false
}

// checkedVarsOf returns the checked borrows in a function (the p of `if p := M.Lookup(k); p != nil`, timer callback arguments).
func (a *analyzer) checkedVarsOf(fn *types.Func, fd *ast.FuncDecl) map[*types.Var]bool {
	out := map[*types.Var]bool{}
	if cb := a.timerCallbacks[fn]; cb != nil && cb.param != nil {
		out[cb.param] = true
	}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok || is.Init == nil {
			return true
		}
		as, ok := is.Init.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 || as.Tok != token.DEFINE {
			return true
		}
		if !a.isMapLookup(as.Rhs[0]) {
			return true
		}
		if id, ok := as.Lhs[0].(*ast.Ident); ok {
			if v, ok := a.info.Defs[id].(*types.Var); ok {
				out[v] = true
			}
		}
		return true
	})
	return out
}

// isMapLookup reports whether e is `M.Lookup(k)` (a map Lookup returning a pointer).
func (a *analyzer) isMapLookup(e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok || len(call.Args) != 1 {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Lookup" {
		return false
	}
	m := a.mapOfExpr(sel.X)
	if m == nil {
		return false
	}
	switch m.Kind {
	case "array", "percpu_array", "hash", "lru_hash", "percpu_hash", "lru_percpu_hash":
		return true
	}
	return false
}

// rootVar returns the root variable if the expression is a variable path (`p.F`, `p.A[i]`, `*p`).
func (a *analyzer) rootVar(e ast.Expr) *types.Var {
	for {
		switch x := ast.Unparen(e).(type) {
		case *ast.SelectorExpr:
			e = x.X
		case *ast.IndexExpr:
			e = x.X
		case *ast.StarExpr:
			e = x.X
		case *ast.Ident:
			v, _ := a.info.Uses[x].(*types.Var)
			return v
		default:
			return nil
		}
	}
}

// resolvePtrParams binds global marks to subprograms, decides borrow argument shapes from the set of all call sites, and checks the callee rules.
func (a *analyzer) resolvePtrParams() {
	progs := map[*types.Func]bool{}
	for _, p := range a.programs {
		progs[p.obj] = true
	}
	var globals []*types.Func
	for fn := range a.globalFuncs {
		globals = append(globals, fn)
	}
	sort.Slice(globals, func(i, j int) bool { return globals[i].Pos() < globals[j].Pos() })
	for _, fn := range globals {
		if s := a.subByObj[fn]; s != nil {
			s.global = true
		} else if !progs[fn] {
			a.report(Rejected, GB013SubprogramShape, a.globalFuncs[fn], []string{fn.Name()}, "//gobpf:global marks an eBPF-side subprogram — %s is not one (not reachable from a program)", fn.Name())
		}
	}
	// the set of call sites
	type site struct {
		pos  token.Pos
		kind string
	}
	sites := map[*ptrParam][]site{}
	decls := a.funcDecls()
	var fns []*types.Func
	for fn := range decls {
		if a.isBPF(fn) || a.timerCallbacks[fn] != nil {
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Pos() < fns[j].Pos() })
	for _, fn := range fns {
		fd := decls[fn]
		if fd.Body == nil {
			continue
		}
		checked := a.checkedVarsOf(fn, fd)
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			cf := a.samePkgFunc(id)
			s := a.subByObj[cf]
			if s == nil || len(s.ptrs) == 0 {
				return true
			}
			for i, pp := range s.ptrs {
				if i >= len(call.Args) {
					continue
				}
				arg := call.Args[i]
				switch {
				case a.isMapLookup(arg):
					sites[pp] = append(sites[pp], site{arg.Pos(), "maybe_ref"})
				case isIdentOf(a, arg, checked):
					sites[pp] = append(sites[pp], site{arg.Pos(), "borrowed"})
				default:
					a.report(Rejected, GB013SubprogramShape, arg.Pos(), []string{fd.Name.Name, s.Symbol}, "the pointer argument of %s must be a checked map value (p of `if p := M.Lookup(k); p != nil`) or `M.Lookup(k)` itself — %s is neither (passing a pointer parameter on to another subprogram is not supported)", s.Symbol, types.ExprString(arg))
					s.ok = false
				}
			}
			return true
		})
	}
	pos := func(p token.Pos) string {
		ps := a.fset.Position(p)
		return fmt.Sprintf("%s:%d:%d", shortFile(ps.Filename), ps.Line, ps.Column)
	}
	for _, s := range a.subs {
		for _, pp := range s.ptrs {
			var bor, may []string
			for _, st := range sites[pp] {
				if st.kind == "borrowed" {
					bor = append(bor, pos(st.pos))
				} else {
					may = append(may, pos(st.pos))
				}
			}
			switch {
			case len(bor) > 0 && len(may) > 0:
				a.report(Rejected, GB013SubprogramShape, s.decl.Name.Pos(), []string{s.Symbol}, "subprogram %s is called with a checked map value for %s (%s) and with an unchecked M.Lookup(k) (%s) — check before passing (`if p := M.Lookup(k); p != nil { %s(p) }`) or use one form everywhere", s.Symbol, pp.obj.Name(), strings.Join(bor, ", "), strings.Join(may, ", "), s.Symbol)
				s.ok = false
			case len(may) > 0:
				pp.kind = "maybe_ref"
			default:
				pp.kind = "borrowed"
			}
			a.checkPtrParamUses(s, pp)
		}
	}
}

func isIdentOf(a *analyzer, e ast.Expr, set map[*types.Var]bool) bool {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return false
	}
	v, _ := a.info.Uses[id].(*types.Var)
	return v != nil && set[v]
}

// checkPtrParamUses checks how a borrow argument is used in the callee: maybe_ref only inside an `if p != nil { … }`
// branch (GB005), and a nil check of borrowed is GB013 (the caller passes a checked value — never nil).
func (a *analyzer) checkPtrParamUses(s *Subprogram, pp *ptrParam) {
	p := pp.obj
	bad := func(code Code, at token.Pos, format string, args ...any) {
		a.report(Rejected, code, at, []string{s.Symbol}, format, args...)
		s.ok = false
	}
	// Writes to a borrow argument (assignment, ++ / --, bpf.AtomicAdd(&p.F, d)) are accepted (bpf-mlir's ref.store, ref.field.store and
	// ref.field.atomic_add in a callee). A non-atomic RMW of a shared map value is GB028 / GB021 at the call site (the callee summary in rmw.go).
	var guarded []*ast.IfStmt
	ast.Inspect(s.decl.Body, func(n ast.Node) bool {
		if x, ok := n.(*ast.IfStmt); ok && x.Init == nil && a.isNilCheckOf(x.Cond, p) {
			guarded = append(guarded, x)
		}
		return true
	})
	if pp.kind == "" { // call sites of both shapes were mixed (GB013 — resolvePtrParams)
		return
	}
	if pp.kind == "borrowed" {
		for _, g := range guarded {
			bad(GB013SubprogramShape, g.Cond.Pos(), "%s is never nil in subprogram %s (every caller passes a checked map value) — remove the check, or pass M.Lookup(k) unchecked everywhere", p.Name(), s.Symbol)
		}
		return
	}
	// maybe_ref: every use is in the condition or branch of `if p != nil { … }`
	inside := func(pos token.Pos) bool {
		for _, g := range guarded {
			if (pos >= g.Cond.Pos() && pos < g.Cond.End()) || (pos >= g.Body.Lbrace && pos < g.Body.Rbrace) {
				return true
			}
		}
		return false
	}
	ast.Inspect(s.decl.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && a.info.Uses[id] == p && !inside(id.Pos()) {
			bad(GB005NilCheckShape, id.Pos(), "use of %s outside `if %s != nil { … }` — callers pass M.Lookup(k) unchecked, so %s may be nil here", p.Name(), p.Name(), p.Name())
		}
		return true
	})
}

// isNilCheckOf reports whether cond is `p != nil` (or `nil != p`).
func (a *analyzer) isNilCheckOf(cond ast.Expr, p *types.Var) bool {
	be, ok := ast.Unparen(cond).(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return false
	}
	isP := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && a.info.Uses[id] == p
	}
	isNil := func(e ast.Expr) bool { return a.info.Types[e].IsNil() }
	return (isP(be.X) && isNil(be.Y)) || (isNil(be.X) && isP(be.Y))
}
