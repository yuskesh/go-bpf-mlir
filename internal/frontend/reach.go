package frontend

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// Reachability sets.
//
// Instead of one label per function ("ebpf" / "user" — user being the complement), each function has the set of roots it is reached from (Membership).
// BPF: follows identifier references to functions of the same package from programs (roots by context type) (a BFS).
// User: follows every identifier reference to functions of the same package from the user roots (calls, callbacks, variables, method values).
//   user roots: main, init, every method (conservatively — calls through an interface cannot be followed statically), package-level variable initializers,
//   and exported functions not reached from BPF (programs and subprograms are not user roots even if exported — calls from another package are outside the frontend).
//   A reference passing a program function to AttachXDP / Objects.Program hands over a handle (not an execution), so it is not an edge.
// The policy is unchanged: a {User, BPF} function (used from both sides) is refused — reported by checkUserSide (GB003 / GB004), with a safety net (GB003) when that gives no diagnostic.

// Membership is the set of roots a function is reached from.
type Membership uint8

const (
	MemUser Membership = 1 << iota
	MemBPF
)

// Has reports whether m contains x.
func (m Membership) Has(x Membership) bool { return m&x != 0 }

// List returns the domain-graph notation (in the order "user", "bpf").
func (m Membership) List() []string {
	out := []string{}
	if m.Has(MemUser) {
		out = append(out, "user")
	}
	if m.Has(MemBPF) {
		out = append(out, "bpf")
	}
	return out
}

// FuncKey is the key of a function instance (function + type arguments). Generic functions are refused for now (GB013 / GB008), so TypeArgs is always empty.
type FuncKey struct {
	Fn       *types.Func // Origin
	TypeArgs string      // the canonical string of the type arguments ("" for non-generic)
}

// keyOf returns the key of a non-generic function (the frontend refuses generic functions for now — GB013 / GB008 — so this suffices for every function).
func keyOf(fn *types.Func) FuncKey { return FuncKey{Fn: fn.Origin()} }

// instanceKey returns the key of an identifier reference — for an instance of a generic function the type arguments are part of the key.
// go/types records the generic function (Origin) in Uses of the identifier `Id[int]` and the type arguments in Instances, so *types.Func alone cannot tell instances apart.
// A plan that accepts generics must build the edges (computeDomains / userRefsIn) with this key.
func instanceKey(info *types.Info, id *ast.Ident) (FuncKey, bool) {
	fn, ok := info.Uses[id].(*types.Func)
	if !ok {
		return FuncKey{}, false
	}
	k := FuncKey{Fn: fn.Origin()}
	if inst, ok := info.Instances[id]; ok && inst.TypeArgs != nil && inst.TypeArgs.Len() > 0 {
		var args []string
		for i := 0; i < inst.TypeArgs.Len(); i++ {
			args = append(args, types.TypeString(inst.TypeArgs.At(i), nil))
		}
		k.TypeArgs = "[" + strings.Join(args, ", ") + "]"
	}
	return k, true
}

// isBPF reports whether fn is reached from a BPF root (what the original "ebpf" label meant).
func (a *analyzer) isBPF(fn *types.Func) bool {
	return fn != nil && a.reach[keyOf(fn)].Has(MemBPF)
}

// userRef is a reference from the user side to an eBPF side function found by checkUserSide (input to the ⊇ test and the safety net).
type userRef struct {
	Owner   string      // the referencing user side function ("(package-level)" for a variable initializer)
	OwnerFn *types.Func // the referencing function (nil for package-level)
	Target  *types.Func // the referenced eBPF side function
}

// computeUserReach follows identifier references from the user roots and adds MemUser to each function reached.
func (a *analyzer) computeUserReach() {
	for fn := range a.userReachSet(nil) {
		a.reach[keyOf(fn)] |= MemUser
	}
}

// userReachSet returns the set of functions reached by following identifier references from the user roots. It does not enter the stop functions (checkSharedReach — the bodies of eBPF side
// functions already reported with GB003 / GB004 are not followed as user reach: a GB003 on a helper inside them would be a chained error).
func (a *analyzer) userReachSet(stop map[*types.Func]bool) map[*types.Func]bool {
	decls := a.funcDecls()
	var work []*types.Func
	seen := map[*types.Func]bool{}
	push := func(fn *types.Func) {
		if fn == nil || seen[fn] || stop[fn] {
			return
		}
		seen[fn] = true
		work = append(work, fn)
	}
	// roots (in declaration position order — deterministic).
	var fns []*types.Func
	for fn := range decls {
		fns = append(fns, fn)
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Pos() < fns[j].Pos() })
	for _, fn := range fns {
		sig := fn.Type().(*types.Signature)
		switch {
		case sig.Recv() != nil: // every method (conservatively, for calls through an interface)
			push(fn)
		case fn.Name() == "main" || fn.Name() == "init":
			push(fn)
		case fn.Exported() && !a.isBPF(fn):
			push(fn)
		}
	}
	// functions referenced by package-level variable initializers.
	for _, f := range a.files() {
		for _, d := range f.Decls {
			if gd, ok := d.(*ast.GenDecl); ok && gd.Tok == token.VAR {
				a.userRefsIn(gd, push)
			}
		}
	}
	for len(work) > 0 {
		fn := work[0]
		work = work[1:]
		if fd := decls[fn]; fd != nil && fd.Body != nil {
			a.userRefsIn(fd.Body, push)
		}
	}
	return seen
}

// userRefsIn pushes identifier references in n to top-level functions of the same package (excluding arguments of AttachXDP / Objects.Program and bpf.TailSlot).
func (a *analyzer) userRefsIn(n ast.Node, push func(*types.Func)) {
	walkWithStack(n, func(x ast.Node, stack []ast.Node) {
		id, ok := x.(*ast.Ident)
		if !ok {
			return
		}
		fn := a.samePkgFunc(id)
		if fn == nil {
			return
		}
		if call, ok := parent(stack, 1).(*ast.CallExpr); ok && call.Fun != ast.Expr(id) && a.programTaker(call) != "" {
			return // handing over a program handle
		}
		if call, ok := parent(stack, 1).(*ast.CallExpr); ok && a.isTailSlotCall(call) && call.Fun != ast.Expr(id) {
			return // the program of a prog_array slot declaration (not an execution; collectTailSlots checks the shape)
		}
		push(fn)
	})
}

// checkSharedReach stops with GB003 the {User, BPF} functions that checkUserSide gave no diagnostic for (a safety net — expected never to fire on current inputs).
func (a *analyzer) checkSharedReach() {
	reported := map[*types.Func]bool{}
	for _, r := range a.userRefs {
		reported[r.Target] = true
	}
	decls := a.funcDecls()
	// user reach that does not follow the bodies of already reported functions (called or used as values from the user side — GB003 / GB004) — a helper reached only from such a body
	// is a chained error, so it is not stopped (for example a helper's GB003 after the GB004 of putting a program function in a slice).
	clean := a.userReachSet(reported)
	var fns []*types.Func
	for k, m := range a.reach {
		if m.Has(MemUser) && m.Has(MemBPF) && !reported[k.Fn] && decls[k.Fn] != nil && clean[k.Fn] {
			fns = append(fns, k.Fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Pos() < fns[j].Pos() })
	for _, fn := range fns {
		a.report(Rejected, GB003CrossDomainUse, decls[fn].Name.Pos(), []string{fn.Name()},
			"%s is reachable both from user space and from a program; functions shared by both sides are not supported", fn.Name())
	}
}

// checkExports stops exported names of eBPF side functions (including program roots) outside package main.
// The frontend does not analyze callers in other packages, so an exported one could be called from user code in another package, and a path that
// panics in the stub of an eBPF-side-only operation would escape the frontend (fail closed). package main is never imported by another package, so it is exempt.
func (a *analyzer) checkExports() {
	if a.pkg.Name == "main" {
		return
	}
	decls := a.funcDecls()
	var fns []*types.Func
	for fn := range decls {
		if a.isBPF(fn) && fn.Exported() {
			fns = append(fns, fn)
		}
	}
	sort.Slice(fns, func(i, j int) bool { return fns[i].Pos() < fns[j].Pos() })
	for _, fn := range fns {
		lower := strings.ToLower(fn.Name()[:1]) + fn.Name()[1:]
		a.report(Rejected, GB019ExportedBPFFunc, decls[fn].Name.Pos(), []string{fn.Name()},
			"the eBPF-side function %s is exported from package %s (not main) — another package could call it and hit the eBPF-only stubs (panic); rename it to %s (attach from outside the package through a user-side function of this package)", fn.Name(), a.pkg.Name, lower)
	}
}
