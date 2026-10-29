package frontend

import (
	"go/ast"
	"go/types"
	"sort"
)

// Closure and summary types.
//
// The closure (the functions, maps and capabilities reachable from a root) is built once per root; the program's maps, the schema program's maps, the capability check (GB011's path)
// and domain-graph's requires all read it. Before, it was computed separately in three places: computeDomains' BFS, usedMaps' recursion and checkCapabilities' BFS.

// FunctionSummary is the per-function summary of the BPF side.
type FunctionSummary struct {
	Key        FuncKey
	Name       string
	Membership Membership
	Own        map[Capability]requirement // capabilities the body needs directly (the first reason per capability)
	Callees    []FuncKey                  // same-package functions the body refers to (in first-reference order, no duplicates)
	Maps       []*BpfMap                  // maps the body refers to directly (declaration order)
}

// BpfClosure is the closure of one root.
type BpfClosure struct {
	Entry    *BpfEntry
	Funcs    []FuncKey                  // BFS order from root (root first)
	Maps     []*BpfMap                  // maps the closure's functions refer to (declaration order)
	Requires map[Capability]requirement // the union of the closure functions' capabilities (first reason in BFS order)
	parent   map[FuncKey]FuncKey        // the BFS tree (path reconstruction — GB011's path)
}

// pathTo returns the function names from root to f.
func (a *analyzer) pathTo(c *BpfClosure, f FuncKey) []string {
	var rev []string
	for k := f; ; {
		rev = append(rev, a.summaries[k].Name)
		p, ok := c.parent[k]
		if !ok {
			break
		}
		k = p
	}
	out := make([]string, len(rev))
	for i := range rev {
		out[i] = rev[len(rev)-1-i]
	}
	return out
}

// buildSummaries builds the summaries of all BPF-side functions (from computeDomains' edges and a walk of the bodies).
func (a *analyzer) buildSummaries() {
	decls := a.funcDecls()
	byName := map[string]FuncKey{}
	for fn := range decls {
		if a.isBPF(fn) {
			byName[fn.Name()] = keyOf(fn)
		}
	}
	a.summaries = map[FuncKey]*FunctionSummary{}
	for fn, fd := range decls {
		if !a.isBPF(fn) || fd.Body == nil {
			continue
		}
		k := keyOf(fn)
		s := &FunctionSummary{Key: k, Name: fn.Name(), Membership: a.reach[k], Own: a.ownRequirements(fd)}
		used := map[*BpfMap]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				if v, ok := a.info.Uses[id].(*types.Var); ok && a.mapByObj[v] != nil {
					used[a.mapByObj[v]] = true
				}
			}
			return true
		})
		for _, m := range a.maps {
			if used[m] {
				s.Maps = append(s.Maps, m)
			}
		}
		a.summaries[k] = s
	}
	// Callees come from computeDomains' edges (reference order), without duplicates.
	seen := map[FuncKey]map[FuncKey]bool{}
	for _, e := range a.graph.Edges {
		if e.Kind != "call" {
			continue
		}
		from, okF := byName[e.From]
		to, okT := byName[e.To]
		if !okF || !okT || a.summaries[from] == nil {
			continue
		}
		if seen[from] == nil {
			seen[from] = map[FuncKey]bool{}
		}
		if !seen[from][to] {
			seen[from][to] = true
			a.summaries[from].Callees = append(a.summaries[from].Callees, to)
		}
	}
}

// buildClosures builds each program's closure once (BFS — callees in reference order).
func (a *analyzer) buildClosures() {
	a.closures = map[*Program]*BpfClosure{}
	for _, p := range a.programs {
		root := keyOf(p.obj)
		c := &BpfClosure{Entry: &p.BpfEntry, Requires: map[Capability]requirement{}, parent: map[FuncKey]FuncKey{}}
		seen := map[FuncKey]bool{root: true}
		queue := []FuncKey{root}
		used := map[*BpfMap]bool{}
		for len(queue) > 0 {
			k := queue[0]
			queue = queue[1:]
			c.Funcs = append(c.Funcs, k)
			s := a.summaries[k]
			if s == nil {
				continue
			}
			for _, cap := range sortedCaps(s.Own) {
				if _, ok := c.Requires[cap]; !ok {
					c.Requires[cap] = s.Own[cap]
				}
			}
			for _, m := range s.Maps {
				used[m] = true
			}
			for _, g := range s.Callees {
				if !seen[g] {
					seen[g] = true
					c.parent[g] = k
					queue = append(queue, g)
				}
			}
		}
		if am := a.attachMapOf(p); am != nil {
			used[am] = true // the attach target sockmap / sockhash goes into the program's maps (even if unused — bpf-mlir's attach symbol)
		}
		for _, m := range a.maps {
			if used[m] {
				c.Maps = append(c.Maps, m)
			}
		}
		a.closures[p] = c
	}
}

// sortedCaps sorts capabilities by the position of their first reason (deterministic).
func sortedCaps(own map[Capability]requirement) []Capability {
	var out []Capability
	for c := range own {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return own[out[i]].pos < own[out[j]].pos })
	return out
}

// transitiveRequires returns the union of the capabilities of functions reachable from f (domain-graph node requires — seen stops cycles).
func (a *analyzer) transitiveRequires(f FuncKey) map[Capability]bool {
	out := map[Capability]bool{}
	seen := map[FuncKey]bool{}
	var walk func(k FuncKey)
	walk = func(k FuncKey) {
		if seen[k] {
			return
		}
		seen[k] = true
		s := a.summaries[k]
		if s == nil {
			return
		}
		for c := range s.Own {
			out[c] = true
		}
		for _, g := range s.Callees {
			walk(g)
		}
	}
	walk(f)
	return out
}
