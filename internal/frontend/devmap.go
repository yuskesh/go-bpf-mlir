package frontend

import (
	"go/ast"
	"go/constant"
	"go/types"
)

// devmap and redirect_map (bpf-mlir's ebpf.redirect_map, feature path F14).
//
//	var Ports = bpf.DevMap{MaxEntries: 8}
//	return Ports.Redirect(ctx, k, bpf.XDPPass)                        → ebpf.redirect_map %m[%k] : …, i32 fallback "pass"
//	return Ports.RedirectIf(ctx, ok, k, bpf.XDPPass, bpf.XDPDrop)     → ebpf.redirect_map %m[%k] : …, i32 fallback "pass" when %ok else "drop"
//
// Only as the last statement of an xdp program body (the same terminator as ctx.Redirect and TailCall). The return value is the helper's — the requested action, not whether delivery succeeded.

// collectDevMap checks and collects devmap declarations (key / value fixed to u32 — a bpf-mlir convention).
// redirectMapKinds maps the bpf type name of a redirect_map target map to its schema kind.
var redirectMapKinds = map[string]string{"DevMap": "devmap", "CPUMap": "cpumap", "DevMapHash": "devmap_hash", "XSKMap": "xskmap"}

// namedBPF returns the name of t if it is a named type of the bpf package ("" otherwise).
func namedBPF(t types.Type) string {
	n, ok := t.(*types.Named)
	if !ok || n.Obj().Pkg() == nil || n.Obj().Pkg().Path() != bpfPkg {
		return ""
	}
	return n.Obj().Name()
}

func (a *analyzer) collectDevMap(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, kind string) {
	u32 := types.Typ[types.Uint32]
	m := &BpfMap{Symbol: obj.Name(), Kind: kind, Pos: a.position(name.Pos()), obj: obj,
		Key: sharedABIOfInt(u32, IntType{32, false}), Value: sharedABIOfInt(u32, IntType{32, false})}
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "%s %s needs an initializer bpf.%s{MaxEntries: N} (MaxEntries is required)", kind, obj.Name(), obj.Type().(*types.Named).Obj().Name())
		return
	}
	if !a.mapInit(m, vs.Values[i]) {
		return
	}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// redirectMapCall returns the map and op if call is DevMap.Redirect / RedirectIf.
func (l *lowerer) redirectMapCall(call *ast.CallExpr) (*BpfMap, string, bool) {
	m, e, _, known := l.mapMethod(call)
	if m == nil || !known || (e.op != "redirect_map" && e.op != "redirect_map_if") {
		return nil, "", false
	}
	return m, e.op, true
}

// redirectMap turns the body's last `return M.Redirect(…)` / `return M.RedirectIf(…)` into ebpf.redirect_map.
func (l *lowerer) redirectMap(call *ast.CallExpr, m *BpfMap, op string) {
	defer l.at(call.Pos())()
	if l.progKind == nil || l.progKind.Kind != "xdp" {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.%s is an xdp terminator (bpf_redirect_map with a %s) — a %s program cannot use it", m.Symbol, sel(call), m.Kind, l.progKind.Kind)
		return
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s.%s must be the program's context parameter", m.Symbol, sel(call))
		return
	}
	verdict := func(e ast.Expr, what string) (string, bool) {
		tv := l.a.info.Types[e]
		if tv.Value != nil {
			if n, exact := constant.Int64Val(tv.Value); exact {
				if name, ok := l.progKind.Verdicts[n]; ok {
					return name, true
				}
			}
		}
		l.fail(Rejected, GB006NonConstant, e.Pos(), "the %s action of %s.%s must be a constant xdp verdict (bpf.XDPAborted / XDPDrop / XDPPass / XDPTx — not a redirect)", what, m.Symbol, sel(call))
		return "", false
	}
	u32 := vtype{bits: 32}
	bt := vtype{isBool: true}
	var cond value
	args := call.Args[1:]
	if op == "redirect_map_if" {
		c, ok := l.expr(args[0], &bt)
		if !ok {
			return
		}
		cond, args = c, args[1:]
	}
	k, ok := l.expr(args[0], &u32)
	if !ok {
		return
	}
	fb, ok := verdict(args[1], "fallback")
	if !ok {
		return
	}
	head := "ebpf.redirect_map " + l.mapArgs[m] + "[" + k.name + "] : " + l.mapType(m) + ", i32 fallback \"" + fb + "\""
	if op == "redirect_map" {
		l.emit("%s", head)
		return
	}
	ow, ok := verdict(args[2], "otherwise")
	if !ok {
		return
	}
	l.emit("%s when %s else %q", head, cond.name, ow)
}

// isRedirectReturn reports whether r is a redirect terminator such as `return ctx.Redirect(…)` / `return M.Redirect(…)` (a review point — a mix of a conditional verdict
// `if c { return A }` and a redirect terminator is not accepted: it is not made a verdict.if, and a return inside an arm still stops with GB001).
func (l *lowerer) isRedirectReturn(r *ast.ReturnStmt) bool {
	if len(r.Results) != 1 {
		return false
	}
	call, ok := r.Results[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	if _, isRedirect := l.redirectOp(call); isRedirect {
		return true
	}
	_, _, isRM := l.redirectMapCall(call)
	_, _, isSK := l.skRedirectCall(call) // sk_skb / sk_msg redirect
	return isRM || isSK
}
