package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// Packet window arguments of subprograms. bpf-mlir's static `ebpf.func` takes
// `!ebpf.pkt_window<N>` (the in_range window of the caller's packet.check) as an argument, and the kernel verifier passes the packet pointer and
// its range through to a static callee as is.
//
//	func keyOf(w bpf.Window) uint32 { … w.BE16(12) … }            // callee — reads follow the caller's rules (constant index, i + width <= N)
//	if w, ok := ctx.Check(0, 24); ok { k = keyOf(w) }              // caller — passes w of the in_range branch directly
//
// Rules (decided over the set of call sites — the same as borrow arguments):
//   - the length N is the same n of Check at every call site (GB013 otherwise — bpf-mlir does not accept shrinking a window either)
//   - static only (a window in `//gobpf:global` is GB013 — the packet range does not reach a global callee)
//   - one window, not together with `*T` (collectSubprograms), not passed on from the callee to another subprogram (GB013 — bpf-mlir accepts it but go is stricter)
//   - writes in the callee (w.SetBE16 and the like) only when every program calling the callee is xdp (GB013 — ebpf-compile names it too)

// checkWinArgs is the switch for the window argument checks (global, differing length, writes from a non-xdp caller, forwarding, window together with *T) — only tests turn it off (the agreement
// test passes the .mlir generated without it to ebpf-compile and separates whether bpf-mlir stops the same shape (global, length, write) or only go does (forwarding, *T)).
// Production builds always check (TestLoopCallCheckSwitchTestOnly).
var checkWinArgs = true

// checkWindowsOf returns w and n of each `if w, ok := ctx.Check(off, n); ok` in a function (where n is a constant — lowering reports the others).
func (a *analyzer) checkWindowsOf(fd *ast.FuncDecl) map[*types.Var]int64 {
	out := map[*types.Var]int64{}
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		is, ok := n.(*ast.IfStmt)
		if !ok || is.Init == nil {
			return true
		}
		as, ok := is.Init.(*ast.AssignStmt)
		if !ok || as.Tok != token.DEFINE || len(as.Lhs) != 2 || len(as.Rhs) != 1 {
			return true
		}
		call, ok := as.Rhs[0].(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); !ok || sel.Sel.Name != "Check" {
			return true
		}
		id, ok := as.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}
		v, _ := a.info.Defs[id].(*types.Var)
		if v == nil || !isBPFNamed(v.Type(), "Window") {
			return true
		}
		tv := a.info.Types[call.Args[1]]
		if tv.Value == nil {
			return true
		}
		if n, exact := constant.Int64Val(constant.ToInt(tv.Value)); exact {
			out[v] = n
		}
		return true
	})
	return out
}

// resolveWinParams decides the length and writability of window arguments from the set of all call sites, and checks the callee rules.
func (a *analyzer) resolveWinParams() {
	type site struct {
		pos  token.Pos
		n    int64
		kind string // the kind of the caller program ("xdp" / "sched_cls" — "" for a caller that is not a program)
		prog string
	}
	sites := map[*Subprogram][]site{}
	forwarded := map[*Subprogram]*Subprogram{} // forwarding in tests with the check off (callee → the forwarding subprogram — the length comes from its window)
	progOf := map[*types.Func]*Program{}
	for _, p := range a.programs {
		progOf[p.obj] = p
	}
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
		wins := a.checkWindowsOf(fd)
		var own *types.Var // the argument, if the caller itself is a subprogram with a window argument (detects forwarding)
		ownSub := a.subByObj[fn]
		if ownSub != nil && ownSub.win != nil {
			own = ownSub.win.obj
		}
		kind, prog := "", ""
		if p := progOf[fn]; p != nil && p.kind != nil {
			kind, prog = p.kind.Kind, p.Symbol
		} else if ownSub != nil && ownSub.ctx != nil { // the Check window of a subprogram that takes the context (kind from the context type)
			kind, prog = ownSub.ctx.Kind, ownSub.Symbol+" (a subprogram taking the "+ownSub.ctx.Kind+" context)"
		}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok {
				return true
			}
			s := a.subByObj[a.samePkgFunc(id)]
			if s == nil || s.win == nil || s.win.idx >= len(call.Args) {
				return true
			}
			arg := call.Args[s.win.idx]
			aid, _ := ast.Unparen(arg).(*ast.Ident)
			var v *types.Var
			if aid != nil {
				v, _ = a.info.Uses[aid].(*types.Var)
			}
			switch {
			case v != nil && v == own && !checkWinArgs:
				forwarded[s] = ownSub
			case v != nil && v == own:
				a.report(Rejected, GB013SubprogramShape, arg.Pos(), []string{fd.Name.Name, s.Symbol}, "subprogram %s passes its packet window %s on to %s — a window is passed only from the program that checked it (call %s from the program with the window of its ctx.Check)", fd.Name.Name, v.Name(), s.Symbol, s.Symbol)
				s.ok = false
			case v != nil && wins[v] > 0:
				sites[s] = append(sites[s], site{arg.Pos(), wins[v], kind, prog})
			default:
				a.report(Rejected, GB013SubprogramShape, arg.Pos(), []string{fd.Name.Name, s.Symbol}, "the packet window argument of %s must be the window w of `if w, ok := ctx.Check(off, n); ok { … }` in the calling program — %s is not", s.Symbol, types.ExprString(arg))
				s.ok = false
			}
			return true
		})
	}
	pos := func(p token.Pos) string {
		ps := a.fset.Position(p)
		return fmt.Sprintf("%s:%d:%d", shortFile(ps.Filename), ps.Line, ps.Column)
	}
	for _, s := range a.subs {
		if s.win == nil {
			continue
		}
		wp := s.win
		if s.global && checkWinArgs {
			a.report(Rejected, GB013SubprogramShape, s.decl.Name.Pos(), []string{s.Symbol}, "global subprogram %s takes a packet window — only a static subprogram can (the kernel verifies a global function on its own and treats a pointer argument as plain memory, not packet data); remove //gobpf:global", s.Symbol)
			s.ok = false
		}
		// writes (w.SetBE16 and the like in the callee)
		ast.Inspect(s.decl.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || wp.writes != token.NoPos {
				return wp.writes == token.NoPos
			}
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if _, isSet := windowStores[sel.Sel.Name]; isSet {
					if rid, ok := sel.X.(*ast.Ident); ok && a.info.Uses[rid] == wp.obj {
						wp.writes = call.Pos()
					}
				}
			}
			return true
		})
		ns := map[int64][]string{}
		for _, st := range sites[s] {
			ns[st.n] = append(ns[st.n], pos(st.pos))
			if checkWinArgs && wp.writes != token.NoPos && st.kind != "xdp" {
				a.report(Rejected, GB013SubprogramShape, st.pos, []string{st.prog, s.Symbol}, "subprogram %s writes the packet through its window %s (%s), but %s program %s calls it — packet writes are xdp-only (bpf-mlir: ebpf.packet.store)", s.Symbol, wp.obj.Name(), pos(wp.writes), st.kind, st.prog)
				s.ok = false
			}
		}
		switch len(ns) {
		case 0:
			// no call site reaches it (caller shape errors are reported above)
		case 1:
			for n := range ns {
				wp.n = n
			}
		default:
			var parts []string
			var keys []int64
			for n := range ns {
				keys = append(keys, n)
			}
			sort.Slice(keys, func(i, j int) bool { return keys[i] < keys[j] })
			if !checkWinArgs {
				wp.n = keys[0] // a test with the check off: the shortest becomes the type — a call with a longer window mismatches (does bpf-mlir stop it?)
				continue
			}
			for _, n := range keys {
				parts = append(parts, fmt.Sprintf("%d at %s", n, strings.Join(ns[n], ", ")))
			}
			a.report(Rejected, GB013SubprogramShape, s.decl.Name.Pos(), []string{s.Symbol}, "subprogram %s is called with packet windows of different lengths (%s) — the window's length is part of its type (bpf-mlir does not narrow a window); check the same length at every call site", s.Symbol, strings.Join(parts, "; "))
			s.ok = false
		}
	}
	for _, s := range a.subs { // forwarding in tests with the check off: the window length of the forwarding subprogram (one level — the caller is called directly from a program)
		if from := forwarded[s]; from != nil && s.win.n == 0 {
			s.win.n = from.win.n
		}
	}
}
