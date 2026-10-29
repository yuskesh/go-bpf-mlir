package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// Non-atomic read-modify-write of shared map values. The verifier accepts these shapes, which silently produce wrong values on multiple CPUs (lost counts); they are stopped at the Go position:
//
//	GB028 (C): op= / ++ / -- on a path of a borrow p (`p := M.Lookup(k)`) of a shared (not per-CPU) map, an `=` that reads the same (or an overlapping) path back
//	          directly or through locals, and `M.Update(k2, e)` carrying a value of the same map (k2 cannot be shown to differ from the Lookup key — fail closed)
//	GB021 (B): d of `M.AtomicAdd(k2, d)` / `M.AddOrInit(k2, d)` on an integer map carries a value of the same map (the keys cannot be shown to differ) — the delta rule of
//	          record bpf.AtomicAdd extended to integer maps
//
// Accepted: per-CPU maps, paths of the lock's record inside a bpf.WithLock region (the lock protects only that record), values of another map or of a key shown to differ,
// and stores that do not read the same path. An RMW of a timer callback's own value (the callback argument) is accepted — a timer's callback never runs concurrently with itself —
// but if the program side (a Lookup borrow) writes the same path of the same map non-atomically, both the callback's RMW and the program's write are stopped with GB028.
// Provenance tracking is as conservative as borrowedFieldCarrier of GB021 (a flow-insensitive fixed point — carries every value through locals, if joins and loops).
//
// **Provenance across subprograms**: two summaries are memoized per subprogram (the call graph is a DAG — recursion is GB010):
//
//	(R) the map reads the return value may carry (map, Lookup key, path) — the caller counts the call expression as those reads
//	(W) where the value of argument i is (transitively) written non-atomically (map, key, path, whether an AtomicAdd delta) — the caller matches them against the reads of the argument expressions and stops at the call position
//
// Keys "differ" only when both are constants with different values (fail closed).

// rmwAcrossCalls enables the cross-subprogram summaries — **only tests set it to false** (a mutation control: with empty summaries the negative examples are accepted again).
var rmwAcrossCalls = true

// rmwSite is one write site.
type rmwSite struct {
	pos  token.Pos
	m    *BpfMap
	path string // the path after the borrow (".N", ".H[i]", "" for the whole value)
	expr string // the expression shown in the message (p.N)
}

// rmwRead is the origin of one read: a borrow in the function (v), a callee's return value (from — the callee's name), or a function argument (param ≥ 0).
type rmwRead struct {
	v      *types.Var // a borrow in the function (if not nil, m and key are that borrow's)
	m      *BpfMap
	key    string // the key expression string (shown in the message — "" for a callback's own value)
	keyVal string // the key's constant value (ExactString of the constant — "" if not constant)
	path   string
	from   string // a read through a callee's return value — the callee's name (for the path message)
	param  int    // the value of function argument i (-1 for a map read)
	// refParam is a read of a path of borrow argument i of the function (-1 otherwise) — mapped to the actual argument's borrow (map, key) at the caller's call position
	refParam int
	through  string // the path words shown in the message ("readN → p.N" and the like)
	// g is a Load read of a global (bpf.Global — .bss) (nil otherwise)
	g *GlobalVar
}

// rmwWrite is one write target of (W).
type rmwWrite struct {
	m      *BpfMap
	key    string
	keyVal string
	path   string
	atomic bool   // the delta of AtomicAdd / AddOrInit (GB021)
	desc   string // the write shape shown in the message ("writeN: p.N = v" and the like)
	// refParam means the target is a path of borrow argument i of the function (-1 otherwise): m and key are mapped from the actual argument's borrow at the call site
	refParam int
	// g means the target is G.Add of a global (nil otherwise; m is nil)
	g *GlobalVar
}

// refRMW is a write to a path of a callee's borrow argument — if rmw is true it is a non-atomic RMW (++ / op= / `=` from its own read).
// It is mapped to the map of the actual argument's borrow at the call site; GB028 for a shared map (per-CPU is accepted).
type refRMW struct {
	param int    // the index of the borrow argument
	pname string // the name of the borrow argument
	path  string
	expr  string // the expression shown in the message (p.N++ and the like)
	pos   token.Pos
	rmw   bool
}

// rmwFacts holds the per-function facts for the verdict (memoized in the analyzer).
type rmwFacts struct {
	diags      []rmwDiag    // verdicts reported for this function (callback / program overlaps come later)
	cbRMW      []rmwSite    // RMWs on paths of the callback argument (candidates to accept)
	progStores []rmwSite    // non-atomic writes to paths of Lookup borrows on the program side (all — for the overlap verdict)
	ret        []rmwRead    // (R) map reads the return value may carry (param < 0)
	writes     [][]rmwWrite // (W) write targets per argument
	refWrites  []refRMW     // writes to paths of borrow arguments (mapped to the caller's map at the call site)
}

type rmwDiag struct {
	code Code
	pos  token.Pos
	msg  string
}

// rmwKey is the memo key — the same function has different facts when read as a timer callback (with the argument as the callback value).
type rmwKey struct {
	decl *ast.FuncDecl
	cb   *types.Var
}

// rmwOf returns the facts of a function (memoized). cbParam / cbMap are a timer callback's argument and bound map (nil otherwise).
func (a *analyzer) rmwOf(decl *ast.FuncDecl, cbParam *types.Var, cbMap *BpfMap) *rmwFacts {
	if a.rmwMemo == nil {
		a.rmwMemo = map[rmwKey]*rmwFacts{}
	}
	k := rmwKey{decl, cbParam}
	if f, ok := a.rmwMemo[k]; ok {
		if f == nil { // recursion (GB010 stops it) — empty facts
			return &rmwFacts{}
		}
		return f
	}
	a.rmwMemo[k] = nil
	f := a.scanRMW(decl, cbParam, cbMap)
	a.rmwMemo[k] = f
	return f
}

// rmwProgStores returns the non-atomic writes to Lookup borrow paths of every eBPF side function that is not a timer callback (for the overlap verdict with callback RMWs).
// **Call it only while lowering a timer callback** — the callback table (a.timerCallbacks) is filled by SetCallback during program lowering, so
// at the start of program lowering a callback would be mistaken for a plain function (an earlier mistake — the overlap verdict was moved to the callback side only).
func (a *analyzer) rmwProgStores() []rmwSite {
	var keys []*types.Func
	decls := a.funcDecls()
	for fn := range decls {
		keys = append(keys, fn)
	}
	sort.Slice(keys, func(i, j int) bool { return keys[i].Pos() < keys[j].Pos() })
	var out []rmwSite
	for _, fn := range keys {
		d := decls[fn]
		if d.Body == nil || a.timerCallbacks[fn] != nil || a.urbCallbacks[fn] != nil || !a.isBPF(fn) {
			continue
		}
		out = append(out, a.rmwOf(d, nil, nil).progStores...)
	}
	return out
}

func pathsOverlap(p, q string) bool {
	return p == q || strings.HasPrefix(p, q) || strings.HasPrefix(q, p)
}

// checkRMW reports non-atomic RMWs in a function body before lowering. false means it reported.
func (l *lowerer) checkRMW(decl *ast.FuncDecl, cbParam *types.Var, cbMap *BpfMap) bool {
	f := l.a.rmwOf(decl, cbParam, cbMap)
	ok := true
	for _, d := range f.diags {
		l.fail(Rejected, d.code, d.pos, "%s", d.msg)
		ok = false
	}
	if cbParam == nil || len(f.cbRMW) == 0 {
		return ok
	}
	// a timer callback's RMW of its own value overlapping a program-side write — stops at both positions (while lowering the callback — rmwProgStores).
	pos := func(p token.Pos) string {
		ps := l.a.fset.Position(p)
		return fmt.Sprintf("%s:%d:%d", shortFile(ps.Filename), ps.Line, ps.Column)
	}
	progStores := l.a.rmwProgStores()
	for _, c := range f.cbRMW {
		for _, s := range progStores {
			if s.m != c.m || !pathsOverlap(s.path, c.path) {
				continue
			}
			l.fail(Rejected, GB028NonAtomicRMW, c.pos, "%s is a non-atomic read-modify-write in the timer callback %s, and a program also writes %s of map %s (%s) — the two can run at the same time on different CPUs; use bpf.AtomicAdd in both, or keep the field to one writer", c.expr, l.name, s.expr, s.m.Symbol, pos(s.pos))
			l.a.report(Rejected, GB028NonAtomicRMW, s.pos, nil, "%s writes a field of map %s that the timer callback %s updates non-atomically (%s) — the two can run at the same time on different CPUs; use bpf.AtomicAdd in both, or keep the field to one writer", s.expr, s.m.Symbol, l.name, pos(c.pos))
			ok = false
		}
	}
	return ok
}

func shortFile(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

type rmwPtr struct {
	m        *BpfMap
	key      ast.Expr // nil for the callback argument
	callback bool
	ref      bool // a borrow argument of a subprogram (m and key come from the caller's actual argument — refParam is the argument index)
	refParam int
}

// keysDiffer reports whether two keys can be shown to differ (both constants with different values — fail closed).
func keysDiffer(x, y string) bool {
	return x != "" && y != "" && x != y
}

// scanRMW walks the body and builds the facts.
func (a *analyzer) scanRMW(decl *ast.FuncDecl, cbParam *types.Var, cbMap *BpfMap) *rmwFacts {
	body := decl.Body
	fnName := decl.Name.Name
	f := &rmwFacts{}
	ptrs := map[*types.Var]rmwPtr{}
	if cbParam != nil && cbMap != nil {
		ptrs[cbParam] = rmwPtr{m: cbMap, callback: true}
	}
	// arguments (except the callback value — integers and bool only: GB013)
	params := map[*types.Var]int{}
	if sig, ok := a.info.Defs[decl.Name].(*types.Func); ok {
		ps := sig.Type().(*types.Signature).Params()
		sub := a.subByObj[sig]
		for i := 0; i < ps.Len(); i++ {
			if sub != nil && sub.ptrs[i] != nil { // a borrow argument (mapped to the map and key of the caller's actual argument)
				ptrs[ps.At(i)] = rmwPtr{ref: true, refParam: i}
				continue
			}
			if sub != nil && sub.win != nil && sub.win.idx == i { // a window argument (unrelated to map value provenance)
				continue
			}
			if ps.At(i) != cbParam {
				params[ps.At(i)] = i
			}
		}
		f.writes = make([][]rmwWrite, ps.Len())
	}
	keyOf := func(e ast.Expr) (string, string) {
		if e == nil {
			return "", ""
		}
		kv := ""
		if tv := a.info.Types[e]; tv.Value != nil {
			kv = tv.Value.ExactString()
		}
		return types.ExprString(e), kv
	}
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr)
		if !ok || len(call.Args) != 1 {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Lookup" {
			return true
		}
		m := a.mapOfExpr(sel.X)
		id, ok := as.Lhs[0].(*ast.Ident)
		if m == nil || !ok {
			return true
		}
		v, _ := a.info.Defs[id].(*types.Var)
		if v == nil {
			v, _ = a.info.Uses[id].(*types.Var)
		}
		if v != nil {
			ptrs[v] = rmwPtr{m: m, key: call.Args[0]}
		}
		return true
	})
	// pathOf returns (borrow, path) if the expression is a borrow path.
	pathOf := func(e ast.Expr) (*types.Var, string, bool) {
		var parts []string
		for {
			switch x := ast.Unparen(e).(type) {
			case *ast.SelectorExpr:
				parts = append([]string{"." + x.Sel.Name}, parts...)
				e = x.X
			case *ast.IndexExpr:
				parts = append([]string{"[" + types.ExprString(x.Index) + "]"}, parts...)
				e = x.X
			case *ast.StarExpr:
				e = x.X
			case *ast.Ident:
				v, _ := a.info.Uses[x].(*types.Var)
				if _, ok := ptrs[v]; ok {
					return v, strings.Join(parts, ""), true
				}
				return nil, "", false
			default:
				return nil, "", false
			}
		}
	}
	localRead := func(v *types.Var, path string) rmwRead {
		if ptrs[v].ref { // a path of a borrow argument (map and key at the caller)
			return rmwRead{path: path, param: -1, refParam: ptrs[v].refParam}
		}
		k, kv := keyOf(ptrs[v].key)
		return rmwRead{v: v, m: ptrs[v].m, key: k, keyVal: kv, path: path, param: -1, refParam: -1}
	}
	// calleeOf returns the declaration if call is a call of a subprogram of the same package.
	calleeOf := func(call *ast.CallExpr) *Subprogram {
		id, ok := call.Fun.(*ast.Ident)
		if !ok {
			return nil
		}
		fn := a.samePkgFunc(id)
		if fn == nil {
			return nil
		}
		if s := a.subByObj[fn]; s != nil && s.decl != nil && s.decl.Body != nil {
			return s
		}
		return nil
	}
	carries := map[*types.Var]map[rmwRead]bool{}
	var reads func(e ast.Node) map[rmwRead]bool
	reads = func(e ast.Node) map[rmwRead]bool {
		got := map[rmwRead]bool{}
		ast.Inspect(e, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				if g := a.globalCallOf(x, "Load"); g != nil { // a global read
					got[rmwRead{g: g, param: -1, refParam: -1}] = true
				}
				if s := calleeOf(x); s != nil && rmwAcrossCalls {
					for _, r := range a.rmwOf(s.decl, nil, nil).ret {
						r.v = nil
						from := s.Symbol
						if r.from != "" {
							from = s.Symbol + " → " + r.from // the callee's callee (transitive)
						}
						if r.refParam >= 0 { // the callee reads and returns a path of a borrow argument: mapped to the actual argument's borrow (map, key)
							if r.refParam < len(x.Args) {
								for r0 := range reads(x.Args[r.refParam]) {
									if r0.m == nil && r0.refParam < 0 {
										continue
									}
									r1 := r0
									r1.v, r1.path, r1.from = nil, r0.path+r.path, from
									got[r1] = true
								}
							}
							continue
						}
						r.from = from
						got[r] = true
					}
				}
			case *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr:
				if v, p, ok := pathOf(x.(ast.Expr)); ok {
					got[localRead(v, p)] = true
					if ix, isIx := x.(*ast.IndexExpr); isIx { // also reads inside the index expression (`p.H[p.I]`)
						for r := range reads(ix.Index) {
							got[r] = true
						}
					}
					return false
				}
			case *ast.Ident:
				if v, ok := a.info.Uses[x].(*types.Var); ok {
					if _, isPtr := ptrs[v]; isPtr {
						got[localRead(v, "")] = true
					}
					if i, isParam := params[v]; isParam {
						got[rmwRead{param: i, refParam: -1}] = true
					}
					for r := range carries[v] {
						got[r] = true
					}
				}
			}
			return true
		})
		return got
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			var lhs, rhs []ast.Expr
			switch x := n.(type) {
			case *ast.AssignStmt:
				if len(x.Lhs) != len(x.Rhs) {
					return true
				}
				lhs, rhs = x.Lhs, x.Rhs
			case *ast.ValueSpec:
				if len(x.Names) != len(x.Values) {
					return true
				}
				for _, nm := range x.Names {
					lhs = append(lhs, nm)
				}
				rhs = x.Values
			default:
				return true
			}
			for i, l := range lhs {
				id, ok := l.(*ast.Ident)
				if !ok || id.Name == "_" {
					continue
				}
				v, _ := a.info.Defs[id].(*types.Var)
				if v == nil {
					v, _ = a.info.Uses[id].(*types.Var)
				}
				if v == nil {
					continue
				}
				if _, isPtr := ptrs[v]; isPtr {
					continue
				}
				for r := range reads(rhs[i]) {
					if carries[v] == nil {
						carries[v] = map[rmwRead]bool{}
					}
					if !carries[v][r] {
						carries[v][r] = true
						changed = true
					}
				}
			}
			return true
		})
	}
	// via returns the path words of a read (" (through …)" if not direct).
	via := func(e ast.Expr, r rmwRead) string {
		if r.from != "" {
			return " (through the return value of " + r.from + ")"
		}
		direct := false
		var carrier string
		ast.Inspect(e, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr, *ast.IndexExpr, *ast.StarExpr:
				if v, p, ok := pathOf(x.(ast.Expr)); ok && v == r.v && pathsOverlap(p, r.path) {
					direct = true
					return false
				}
			case *ast.Ident:
				if v, ok := a.info.Uses[x].(*types.Var); ok && carrier == "" && carries[v][r] {
					carrier = x.Name
				}
			}
			return true
		})
		if direct || carrier == "" {
			return ""
		}
		return " (through the local variable " + carrier + ")"
	}
	percpu := func(m *BpfMap) bool { return strings.Contains(m.Kind, "percpu") }
	keyText := func(r rmwRead) string {
		if r.key == "" {
			return "the callback's own value"
		}
		return "key " + r.key
	}
	fix := "use bpf.AtomicAdd / M.AtomicAdd, a per-CPU map, or bpf.WithLock"
	// (R) — map reads carried by the return value.
	ast.Inspect(body, func(n ast.Node) bool {
		if _, isLit := n.(*ast.FuncLit); isLit {
			return false
		}
		if rs, ok := n.(*ast.ReturnStmt); ok {
			for _, e := range rs.Results {
				for _, r := range sortedReads(reads(e)) {
					if r.param < 0 && (r.m != nil || r.refParam >= 0 || r.g != nil) { // map reads, reads of borrow argument paths, global reads
						r.v = nil
						if r.from == "" {
							r.through = fnName
						}
						f.ret = append(f.ret, r)
					}
				}
			}
		}
		return true
	})
	var walk func(n ast.Node, locked *types.Var)
	walk = func(n ast.Node, locked *types.Var) {
		ast.Inspect(n, func(m ast.Node) bool {
			switch x := m.(type) {
			case *ast.CallExpr:
				if a.isBpfFunc(x, "WithLock") && len(x.Args) == 2 {
					var root *types.Var
					if u, ok := ast.Unparen(x.Args[0]).(*ast.UnaryExpr); ok && u.Op == token.AND {
						root, _, _ = pathOf(u.X)
					}
					if fl, ok := x.Args[1].(*ast.FuncLit); ok {
						walk(fl.Body, root)
					}
					return false
				}
				// (W) — matches where the callee writes argument values against the reads of the argument expressions.
				if s := calleeOf(x); s != nil && rmwAcrossCalls {
					cf := a.rmwOf(s.decl, nil, nil)
					// the borrow (map, key) of the actual argument for the callee's borrow argument j — a checked borrow variable or an `M.Lookup(k)` expression.
					refArg := func(j int) (rmwPtr, *types.Var, bool) {
						if j >= len(x.Args) {
							return rmwPtr{}, nil, false
						}
						arg := ast.Unparen(x.Args[j])
						if a.isMapLookup(arg) {
							c := arg.(*ast.CallExpr)
							return rmwPtr{m: a.mapOfExpr(c.Fun.(*ast.SelectorExpr).X), key: c.Args[0]}, nil, true
						}
						if id, ok := arg.(*ast.Ident); ok {
							v, _ := a.info.Uses[id].(*types.Var)
							if p, ok := ptrs[v]; ok && !p.ref && p.m != nil {
								return p, v, true
							}
						}
						return rmwPtr{}, nil, false // forwarding a borrow argument is GB013 (subargs.go)
					}
					for _, rw := range cf.refWrites {
						p, root, ok := refArg(rw.param)
						if !ok || percpu(p.m) || root != nil && root == locked {
							continue
						}
						site := rmwSite{x.Pos(), p.m, rw.path, s.Symbol + ": " + rw.expr}
						if p.callback { // a timer callback's own value — the callback RMW rule (overlap with program writes)
							if rw.rmw {
								f.cbRMW = append(f.cbRMW, site)
							}
							continue
						}
						f.progStores = append(f.progStores, site)
						if rw.rmw {
							k, _ := keyOf(p.key)
							ps := a.fset.Position(rw.pos)
							f.diags = append(f.diags, rmwDiag{GB028NonAtomicRMW, x.Pos(), fmt.Sprintf("%s(…) does %s (%s:%d:%d) through its pointer parameter %s, and here it is passed a value of the shared map %s (key %s) — a non-atomic read-modify-write (another CPU can update the value between the read and the write — lost updates); %s", s.Symbol, rw.expr, shortFile(ps.Filename), ps.Line, ps.Column, rw.pname, p.m.Symbol, k, fix)})
						}
					}
					for j, arg := range x.Args {
						if j >= len(cf.writes) {
							break
						}
						reported := false
						for _, w := range cf.writes[j] {
							if reported {
								break
							}
							if w.refParam >= 0 { // the target is a borrow argument of the callee — mapped to the actual argument's borrow
								p, _, ok := refArg(w.refParam)
								if !ok {
									continue
								}
								w.m, w.refParam = p.m, -1
								w.key, w.keyVal = keyOf(p.key)
								if p.callback {
									w.key = "the callback's own value"
								}
							}
							for _, r := range sortedReads(reads(arg)) {
								if r.param >= 0 { // passes an argument value through — added to this function's argument write targets (transitive)
									if r.param < len(f.writes) {
										w2 := w
										w2.desc = fnName + " → " + w.desc
										f.writes[r.param] = append(f.writes[r.param], w2)
									}
									continue
								}
								if w.g != nil { // the callee Adds an argument value to a global
									if r.g != w.g {
										continue
									}
									f.diags = append(f.diags, rmwDiag{GB021AtomicShape, x.Pos(), fmt.Sprintf("%s(…) adds its argument %d to the global %s (%s), and the argument reads %s%s here — an atomic add whose delta reads the same global — the read and the add are not one atomic step (another CPU can add in between); use a delta from a constant, another global or map, or the packet", s.Symbol, j+1, w.g.Symbol, w.desc, w.g.Symbol, via(arg, r))})
									reported = true
									break
								}
								// an atomic write target is per record (the same as sameRef of the lowerer's GB021 — reading another field of the same record also stops)
								if r.m != w.m || percpu(w.m) || keysDiffer(r.keyVal, w.keyVal) || (!w.atomic && !pathsOverlap(r.path, w.path)) {
									continue
								}
								code, what := GB028NonAtomicRMW, "a non-atomic read-modify-write across the call"
								if w.atomic {
									code, what = GB021AtomicShape, "an atomic add whose delta reads the same value — the read and the add are not one atomic step"
								}
								f.diags = append(f.diags, rmwDiag{code, x.Pos(), fmt.Sprintf("%s(…) writes its argument %d to %s[%s]%s (%s), and the argument reads %s[%s]%s%s here — %s (another CPU can update the value in between; the keys are not shown to differ); %s", s.Symbol, j+1, w.m.Symbol, w.key, w.path, w.desc, r.m.Symbol, strings.TrimPrefix(keyText(r), "key "), r.path, via(arg, r), what, fix)})
								reported = true
								break
							}
						}
					}
					return true
				}
				// d of the callee's bpf.AtomicAdd(&p.F, d) (p a borrow argument) carries integer argument i — an atomic write target of (W).
				// d reading a field of p itself (through locals) is stopped by the lowerer's GB021 (sameRef, borrowedFieldCarrier).
				// (M.AtomicAdd(k, d) — a map method — is also AtomicAdd of the bpf package, so only the shape with &… as the first argument is handled here)
				if u, isAddr := firstArgAddr(x); isAddr && a.isBpfFunc(x, "AtomicAdd") && len(x.Args) == 2 {
					if v, path, ok := pathOf(u.X); ok && ptrs[v].ref {
						for _, r := range sortedReads(reads(x.Args[1])) {
							if r.param >= 0 && r.param < len(f.writes) {
								f.writes[r.param] = append(f.writes[r.param], rmwWrite{path: path, atomic: true, desc: fmt.Sprintf("%s: bpf.AtomicAdd(&%s, …)", fnName, types.ExprString(u.X)), refParam: ptrs[v].refParam})
							}
						}
					}
					return true
				}
				// G.Add(d) whose d carries a Load of the same global is GB021 (the same as the AtomicAdd delta of an integer map); if d carries argument i it is (W).
				if g := a.globalCallOf(x, "Add"); g != nil && len(x.Args) == 1 {
					for _, r := range sortedReads(reads(x.Args[0])) {
						if r.param >= 0 {
							if r.param < len(f.writes) {
								f.writes[r.param] = append(f.writes[r.param], rmwWrite{g: g, atomic: true, desc: fmt.Sprintf("%s: %s.Add(…)", fnName, g.Symbol), refParam: -1})
							}
							continue
						}
						if r.g == g {
							f.diags = append(f.diags, rmwDiag{GB021AtomicShape, x.Args[0].Pos(), fmt.Sprintf("the delta of %s.Add reads the same global %s%s — the read and the add are not one atomic step (another CPU can add in between); use a delta from a constant, another global or map, or the packet", g.Symbol, g.Symbol, via(x.Args[0], r))})
							break
						}
					}
					return true
				}
				sel, ok := x.Fun.(*ast.SelectorExpr)
				if !ok || len(x.Args) != 2 || (sel.Sel.Name != "Update" && sel.Sel.Name != "AtomicAdd" && sel.Sel.Name != "AddOrInit") {
					return true
				}
				mm := a.mapOfExpr(sel.X)
				if mm == nil || percpu(mm) {
					return true
				}
				k2, kv2 := keyOf(x.Args[0])
				atomic := sel.Sel.Name != "Update"
				for _, r := range sortedReads(reads(x.Args[1])) {
					if r.param >= 0 { // writes an argument value — (W)
						if r.param < len(f.writes) {
							f.writes[r.param] = append(f.writes[r.param], rmwWrite{m: mm, key: k2, keyVal: kv2, atomic: atomic, desc: fmt.Sprintf("%s: %s.%s(%s, …)", fnName, mm.Symbol, sel.Sel.Name, k2), refParam: -1})
						}
						continue
					}
					if r.m != mm || keysDiffer(r.keyVal, kv2) {
						continue
					}
					if !atomic {
						f.diags = append(f.diags, rmwDiag{GB028NonAtomicRMW, x.Pos(), fmt.Sprintf("%s.Update(%s, …) writes back a value read from %s (%s)%s — the keys are not shown to differ, so this is a non-atomic read-modify-write of a shared map value (another CPU can update it in between); write to a different map or a key shown to differ (a different constant), or %s", mm.Symbol, k2, mm.Symbol, keyText(r), via(x.Args[1], r), fix)})
					} else {
						f.diags = append(f.diags, rmwDiag{GB021AtomicShape, x.Args[1].Pos(), fmt.Sprintf("the delta of %s.%s reads a value of the same map %s (%s)%s — the keys are not shown to differ, so the read and the add are not one atomic step (another CPU can update the value in between); use a delta from a constant, another map, the packet or a key shown to differ", mm.Symbol, sel.Sel.Name, mm.Symbol, keyText(r), via(x.Args[1], r))})
					}
					break
				}
			case *ast.IncDecStmt:
				v, path, ok := pathOf(x.X)
				if ok && ptrs[v].ref { // an RMW on a borrow argument path — mapped to the actual argument's map at the call site
					f.refWrites = append(f.refWrites, refRMW{ptrs[v].refParam, v.Name(), path, types.ExprString(x.X) + x.Tok.String(), x.Pos(), true})
					return true
				}
				if !ok || percpu(ptrs[v].m) || v == locked {
					return true
				}
				site := rmwSite{x.Pos(), ptrs[v].m, path, types.ExprString(x.X)}
				if ptrs[v].callback {
					f.cbRMW = append(f.cbRMW, site)
					return true
				}
				f.progStores = append(f.progStores, site)
				f.diags = append(f.diags, rmwDiag{GB028NonAtomicRMW, x.Pos(), fmt.Sprintf("%s%s is a non-atomic read-modify-write of a value in the shared map %s (another CPU can update it between the read and the write — lost updates); %s", types.ExprString(x.X), x.Tok, ptrs[v].m.Symbol, fix)})
			case *ast.AssignStmt:
				for i, lh := range x.Lhs {
					v, path, ok := pathOf(lh)
					if ok && ptrs[v].ref { // a write to a borrow argument path
						j := ptrs[v].refParam
						rw := refRMW{j, v.Name(), path, types.ExprString(lh) + " " + x.Tok.String() + " …", lh.Pos(), x.Tok != token.ASSIGN && x.Tok != token.DEFINE}
						if !rw.rmw && i < len(x.Rhs) {
							for _, r := range sortedReads(reads(x.Rhs[i])) {
								if r.param >= 0 { // (i) writes an argument value to a borrow argument path — a (W) target (with refParam)
									if r.param < len(f.writes) {
										f.writes[r.param] = append(f.writes[r.param], rmwWrite{path: path, desc: fmt.Sprintf("%s: %s = …", fnName, types.ExprString(lh)), refParam: j})
									}
									continue
								}
								if r.m == nil && r.refParam == j && pathsOverlap(r.path, path) { // (ii) `=` from a read of its own path (even through locals or callee return values)
									rw.rmw = true
									rw.expr = types.ExprString(lh) + " = …" + types.ExprString(lh) + "…" + via(x.Rhs[i], r)
									break
								}
							}
						}
						f.refWrites = append(f.refWrites, rw)
						continue
					}
					if !ok || percpu(ptrs[v].m) || v == locked {
						continue
					}
					site := rmwSite{lh.Pos(), ptrs[v].m, path, types.ExprString(lh)}
					lk, lkv := keyOf(ptrs[v].key)
					var msg string
					switch {
					case x.Tok != token.ASSIGN && x.Tok != token.DEFINE:
						msg = fmt.Sprintf("%s %s … is a non-atomic read-modify-write of a value in the shared map %s (another CPU can update it between the read and the write — lost updates); %s", types.ExprString(lh), x.Tok, ptrs[v].m.Symbol, fix)
					case i < len(x.Rhs):
						for _, r := range sortedReads(reads(x.Rhs[i])) {
							if r.param >= 0 { // writes an argument value to a borrow path — (W)
								if !ptrs[v].callback && r.param < len(f.writes) {
									f.writes[r.param] = append(f.writes[r.param], rmwWrite{m: ptrs[v].m, key: lk, keyVal: lkv, path: path, desc: fmt.Sprintf("%s: %s = …", fnName, types.ExprString(lh)), refParam: -1})
								}
								continue
							}
							same := r.v == v && pathsOverlap(r.path, path)
							fromCall := r.v == nil && r.from != "" && r.m == ptrs[v].m && !keysDiffer(r.keyVal, lkv) && pathsOverlap(r.path, path)
							if same || fromCall {
								msg = fmt.Sprintf("%s is written from a value read from itself%s — a non-atomic read-modify-write of a value in the shared map %s (another CPU can update it between the read and the write — lost updates); %s", types.ExprString(lh), via(x.Rhs[i], r), ptrs[v].m.Symbol, fix)
								break
							}
						}
					}
					if ptrs[v].callback {
						if msg != "" {
							f.cbRMW = append(f.cbRMW, site)
						}
						continue
					}
					f.progStores = append(f.progStores, site)
					if msg != "" {
						f.diags = append(f.diags, rmwDiag{GB028NonAtomicRMW, lh.Pos(), msg})
					}
				}
			}
			return true
		})
	}
	walk(body, nil)
	return f
}

// sortedReads sorts a set of reads in a fixed order (a bug found by the gate: with map order the first matching read changed, and the message's "through …"
// varied from run to run). Reads through a callee (with from set) come first — the message names more.
func sortedReads(m map[rmwRead]bool) []rmwRead {
	out := make([]rmwRead, 0, len(m))
	for r := range m {
		out = append(out, r)
	}
	key := func(r rmwRead) string {
		first := "1"
		if r.from != "" {
			first = "0"
		}
		name, mp := "", ""
		if r.v != nil {
			name = r.v.Name()
		}
		if r.m != nil {
			mp = r.m.Symbol
		}
		if r.g != nil {
			mp = "global:" + r.g.Symbol
		}
		return fmt.Sprintf("%s|%s|%s|%s|%s|%d|%d|%s", first, r.from, mp, r.key, r.path, r.param, r.refParam, name)
	}
	sort.Slice(out, func(i, j int) bool { return key(out[i]) < key(out[j]) })
	return out
}

// mapOfExpr returns the map if the expression is a map variable.
func (a *analyzer) mapOfExpr(e ast.Expr) *BpfMap {
	id, ok := ast.Unparen(e).(*ast.Ident)
	if !ok {
		return nil
	}
	v, _ := a.info.Uses[id].(*types.Var)
	if m := a.mapByObj[v]; m != nil {
		return m
	}
	return a.innerByVar[v] // the inner handle of a map-in-map (the inner map is shared too)
}

// globalCallOf returns the global if call is `G.<method>(…)` (G a bpf.Global — .bss). bpf.Config (.rodata) is read-only and out of scope.
func (a *analyzer) globalCallOf(call *ast.CallExpr, method string) *GlobalVar {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != method {
		return nil
	}
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok {
		return nil
	}
	v, _ := a.info.Uses[id].(*types.Var)
	if g := a.globalByObj[v]; g != nil && g.Section == "bss" {
		return g
	}
	return nil
}

// firstArgAddr returns x if the first argument of call is `&x`.
func firstArgAddr(call *ast.CallExpr) (*ast.UnaryExpr, bool) {
	if len(call.Args) == 0 {
		return nil, false
	}
	u, ok := ast.Unparen(call.Args[0]).(*ast.UnaryExpr)
	return u, ok && u.Op == token.AND
}

// isBpfFunc reports whether call is a call of the bpf package function name (including explicit type arguments `bpf.AtomicAdd[uint64](…)` — a gap found earlier).
func (a *analyzer) isBpfFunc(call *ast.CallExpr, name string) bool {
	fun := ast.Unparen(call.Fun)
	switch f := fun.(type) {
	case *ast.IndexExpr:
		fun = f.X
	case *ast.IndexListExpr:
		fun = f.X
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	fn, ok := a.info.Uses[sel.Sel].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == bpfPkg
}
