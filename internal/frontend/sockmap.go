package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// sockmap, sockhash and sk_skb (bpf-mlir's sk.redirect):
//
//	var Socks = bpf.SockMap{MaxEntries: 2}
//
//	//gobpf:sk_skb Socks
//	func f(ctx *bpf.SKSKBContext) bpf.SKAction {
//		return Socks.RedirectIf(ctx, ctx.Len() == 7, 1, bpf.SKIngress, bpf.SKPass)
//	}
//	→ ebpf.program @f "sk_skb" attach "Socks" maps [@Socks]
//	  ebpf.sk.redirect %ctx, %m0[%k] ingress : !ebpf.ctx<"sk_skb">, !ebpf.map<"sockmap", i32, i32>, i32 when %c else "pass"
//
// The map value is a socket fd (u32 — set by the user-space side). The only eBPF side ops are the terminal Redirect / RedirectIf (a top-level return of the body — the same rule as DevMap).
// The attach target map goes into the program's maps (even if unused — bpf-mlir's attach symbol).

// sockMapKinds maps a bpf type name to a schema kind.
var sockMapKinds = map[string]string{"SockMap": "sockmap", "SockHash": "sockhash", "ReuseportSockArray": "reuseport_sockarray", "CgroupArray": "cgroup_array"} // cgroup_array: key u32, value u32 fd

// collectSockMap collects sockmap / sockhash declarations (the sockmap key is u32, the sockhash key is K, the value is u32). reuseport_sockarray
// has key u32 and value u64 (a user-space lookup returns the socket cookie — the same as bpf-mlir's schema).
func (a *analyzer) collectSockMap(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, kind string) {
	u32 := types.Typ[types.Uint32]
	key := sharedABIOfInt(u32, IntType{32, false})
	if kind == "sockhash" {
		n := obj.Type().(*types.Named)
		kt := n.TypeArgs().At(0)
		it, ok := intTypeOf(kt)
		if !ok {
			a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "sockhash %s: the key type %s must be an 8 / 16 / 32 / 64-bit integer", obj.Name(), kt)
			return
		}
		key = sharedABIOfInt(kt, it)
	}
	val := sharedABIOfInt(u32, IntType{32, false})
	if kind == "reuseport_sockarray" {
		val = sharedABIOfInt(types.Typ[types.Uint64], IntType{64, false})
	}
	m := &BpfMap{Symbol: obj.Name(), Kind: kind, Pos: a.position(name.Pos()), obj: obj, Key: key, Value: val}
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

// sockmapDirective reads the one word of `//gobpf:sk_skb <map>` — the name of a sockmap / sockhash variable of this package.
func (a *analyzer) sockmapDirective(fd *ast.FuncDecl, at token.Pos, kind string, fields []string) (string, int, bool) {
	if len(fields) != 1 || !cIdent.MatchString(fields[0]) {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s takes the name of one sockmap / sockhash variable of this package (`%s`), got %v", kind, directiveUsage(kind), fields)
		return "", 0, false
	}
	for _, m := range a.maps {
		if m.Symbol != fields[0] {
			continue
		}
		if m.Kind != "sockmap" && m.Kind != "sockhash" {
			a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s %s: %s is a %s map — a %s program attaches to a bpf.SockMap or bpf.SockHash", kind, fields[0], fields[0], m.Kind, kind)
			return "", 0, false
		}
		return fields[0], 0, true
	}
	a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s %s: no bpf.SockMap / bpf.SockHash variable named %s in this package", kind, fields[0], fields[0])
	return "", 0, false
}

// attachMapOf returns the attach target map of a program attached to a sockmap (the directive's name — nil if none).
func (a *analyzer) attachMapOf(p *Program) *BpfMap {
	if p.ProgramType == "iter" { // the iterator's target map (the program does not read it — in the program's maps so it is in the ELF)
		for _, m := range a.maps {
			if m.Symbol == p.IterMap {
				return m
			}
		}
		return nil
	}
	if !isSockmapProgKind(p.ProgramType) {
		return nil
	}
	for _, m := range a.maps {
		if m.Symbol == p.Attach && (m.Kind == "sockmap" || m.Kind == "sockhash") {
			return m
		}
	}
	return nil
}

// skRedirectCall returns the map and op if call is Redirect / RedirectIf of a SockMap / SockHash.
func (l *lowerer) skRedirectCall(call *ast.CallExpr) (*BpfMap, string, bool) {
	m, e, _, known := l.mapMethod(call)
	if m == nil || !known || (e.op != "sk_redirect" && e.op != "sk_redirect_if" && e.op != "msg_redirect" && e.op != "msg_redirect_if") {
		return nil, "", false
	}
	return m, e.op, true
}

// skRedirect lowers the final `return M.Redirect(ctx, k, dir)` / `return M.RedirectIf(ctx, cond, k, dir, otherwise)` of the body to ebpf.sk.redirect,
// and `M.MsgRedirect` / `M.MsgRedirectIf` to ebpf.msg.redirect (sk_msg).
func (l *lowerer) skRedirect(call *ast.CallExpr, m *BpfMap, op string) {
	defer l.at(call.Pos())()
	want, mop, helper := "sk_skb", "ebpf.sk.redirect", "bpf_sk_redirect_map / _hash"
	if op == "msg_redirect" || op == "msg_redirect_if" {
		want, mop, helper = "sk_msg", "ebpf.msg.redirect", "bpf_msg_redirect_map / _hash"
		op = map[string]string{"msg_redirect": "sk_redirect", "msg_redirect_if": "sk_redirect_if"}[op]
	}
	if l.progKind == nil || l.progKind.Kind != want {
		kind := "subprogram"
		if l.progKind != nil {
			kind = l.progKind.Kind
		}
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.%s is an %s terminator (%s) — a %s program cannot use it", m.Symbol, sel(call), want, helper, kind)
		return
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s.%s must be the program's context parameter", m.Symbol, sel(call))
		return
	}
	bt := vtype{isBool: true}
	var cond value
	args := call.Args[1:]
	if op == "sk_redirect_if" {
		c, ok := l.expr(args[0], &bt)
		if !ok {
			return
		}
		cond, args = c, args[1:]
	}
	kt := vtypeOf(*m.Key.Int)
	k, ok := l.expr(args[0], &kt)
	if !ok {
		return
	}
	ingress := ""
	if tv := l.a.info.Types[args[1]]; tv.Value == nil {
		l.fail(Rejected, GB006NonConstant, args[1].Pos(), "the direction of %s.%s must be a constant (bpf.SKIngress / bpf.SKEgress)", m.Symbol, sel(call))
		return
	} else if n, _ := constant.Int64Val(tv.Value); n == 1 {
		ingress = " ingress"
	}
	head := mop + " %ctx, " + l.mapArgs[m] + "[" + k.name + "]" + ingress + " : !ebpf.ctx<\"" + want + "\">, " + l.mapType(m) + ", " + kt.mlir()
	if op == "sk_redirect" {
		l.emit("%s", head)
		return
	}
	tv := l.a.info.Types[args[2]]
	name := ""
	if tv.Value != nil {
		if n, exact := constant.Int64Val(tv.Value); exact {
			name = l.progKind.Verdicts[n]
		}
	}
	if name == "" {
		l.fail(Rejected, GB006NonConstant, args[2].Pos(), "the otherwise action of %s.%s must be a constant %s verdict (bpf.SKPass / bpf.SKDrop)", m.Symbol, sel(call), want)
		return
	}
	l.emit("%s when %s else %q", head, cond.name, name)
}

// reuseportSelect lowers sk_reuseport's `st := M.Select(ctx, k)` to `%st = ebpf.sk.select_reuseport %ctx, %m[%k] : !ebpf.ctx<"sk_reuseport">,
// !ebpf.map<"reuseport_sockarray", i32, i64>, i32 -> i64` (the raw status; only in the body of an sk_reuseport program, outside loops).
func (l *lowerer) reuseportSelect(call *ast.CallExpr, m *BpfMap) (value, bool) {
	defer l.at(call.Pos())()
	if l.progKind == nil || l.progKind.Kind != "sk_reuseport" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.Select chooses the receiving socket of a SO_REUSEPORT group — it may only be called in the body of a sk_reuseport program (func f(ctx *bpf.SkReuseportContext) bpf.SKAction)", m.Symbol)
		return value{}, false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.Select cannot be called inside a loop (bpf-mlir does not allow sk.select_reuseport in a loop body) — call it before the loop", m.Symbol)
		return value{}, false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s.Select must be the program's context parameter", m.Symbol)
		return value{}, false
	}
	kt := vtypeOf(*m.Key.Int)
	k, ok := l.expr(call.Args[1], &kt)
	if !ok {
		return value{}, false
	}
	r := l.val()
	l.emit("%s = ebpf.sk.select_reuseport %%ctx, %s[%s] : !ebpf.ctx<\"sk_reuseport\">, %s, %s -> i64", r, l.mapArgs[m], k.name, l.mapType(m), kt.mlir())
	return value{r, vtype{bits: 64, signed: true}}, true
}

// sockInsert lowers sock_ops's `st := M.Insert(ctx, k, flags)` to `%st = ebpf.sock.map_update %ctx, %m[%k] flags "<any|noexist|exist>" : …-> i64`
// (the raw status; only in the body of a sock_ops program, outside loop bodies, flags a constant).
func (l *lowerer) sockInsert(call *ast.CallExpr, m *BpfMap) (value, bool) {
	defer l.at(call.Pos())()
	if l.progKind == nil || l.progKind.Kind != "sock_ops" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.Insert puts the socket of a sock_ops callback into the map — it may only be called in the body of a sock_ops program (func f(ctx *bpf.SockOpsContext) bpf.CgroupAction)", m.Symbol)
		return value{}, false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.Insert cannot be called inside a loop (bpf-mlir does not allow sock.map_update in a loop body)", m.Symbol)
		return value{}, false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s.Insert must be the program's context parameter", m.Symbol)
		return value{}, false
	}
	tv := l.a.info.Types[call.Args[2]]
	flags := ""
	if tv.Value != nil {
		if n, exact := constant.Int64Val(tv.Value); exact {
			flags = map[int64]string{0: "any", 1: "noexist", 2: "exist"}[n]
		}
	}
	if flags == "" {
		l.fail(Rejected, GB006NonConstant, call.Args[2].Pos(), "the flags of %s.Insert must be the constant bpf.SockAny, bpf.SockNoExist or bpf.SockExist", m.Symbol)
		return value{}, false
	}
	kt := vtypeOf(*m.Key.Int)
	k, ok := l.expr(call.Args[1], &kt)
	if !ok {
		return value{}, false
	}
	r := l.val()
	l.emit("%s = ebpf.sock.map_update %%ctx, %s[%s] flags %q : !ebpf.ctx<\"sock_ops\">, %s, %s -> i64", r, l.mapArgs[m], k.name, flags, l.mapType(m), kt.mlir())
	return value{r, vtype{bits: 64, signed: true}}, true
}

// skAssignFlags maps a SkAssignFlags constant value to the sk.assign keyword (sklookupflag in bpf-mlir's UAPI table — replace 1, no_reuseport 2).
var skAssignFlags = map[int64]string{0: "", 1: " replace", 2: " no_reuseport", 3: " replace no_reuseport"}

// skAssignAssign lowers `st, found := M.Assign(ctx, k, flags)` (the body of an sk_lookup program, `_` allowed). handled reports whether the right-hand side of s
// is that call. The socket reference is not exposed to Go — lookup, check, assign and release form one group:
//
//	%s = ebpf.sock.map_lookup %m[%k] : !ebpf.map<"sockmap", i32, i32>, i32 -> !ebpf.sock_ref_or_null
//	%r:2 = ebpf.sock.ref_check %s : !ebpf.sock_ref_or_null -> i64, i8 present {
//	^p(%sk: !ebpf.sock_ref):
//	  %a = ebpf.sk.assign %ctx, %sk (replace)? (no_reuseport)? : !ebpf.ctx<"sk_lookup">, !ebpf.sock_ref -> i64
//	  ebpf.sock.release %sk : !ebpf.sock_ref
//	  ebpf.yield %a, 1 : i64, i8
//	} absent { ebpf.yield 0, 0 : i64, i8 }
func (l *lowerer) skAssignAssign(s *ast.AssignStmt) bool {
	if len(s.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	m, e, _, known := l.mapMethod(call)
	if m == nil || !known || e.op != "sk_assign" {
		return false
	}
	defer l.at(call.Pos())()
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
		return true
	}
	if !l.skAssignPlace(m, call) {
		return true
	}
	tv := l.a.info.Types[call.Args[2]]
	flags, fok := "", false
	if tv.Value != nil {
		if n, exact := constant.Int64Val(tv.Value); exact {
			flags, fok = skAssignFlags[n]
		}
	}
	if !fok {
		l.fail(Rejected, GB006NonConstant, call.Args[2].Pos(), "the flags of %s.Assign must be a constant: 0, bpf.SkAssignReplace, bpf.SkAssignNoReuseport or both joined with |", m.Symbol)
		return true
	}
	kt := vtypeOf(*m.Key.Int)
	k, ok := l.expr(call.Args[1], &kt)
	if !ok {
		return true
	}
	i64, i8 := vtype{bits: 64, signed: true}, vtype{bits: 8}
	sr := l.val()
	l.emit("%s = ebpf.sock.map_lookup %s[%s] : %s, %s -> !ebpf.sock_ref_or_null", sr, l.mapArgs[m], k.name, l.mapType(m), kt.mlir())
	sk := l.val()
	present := l.region(func() {
		a := l.val()
		l.emit("%s = ebpf.sk.assign %%ctx, %s%s : !ebpf.ctx<\"sk_lookup\">, !ebpf.sock_ref -> i64", a, sk, flags)
		l.emit("ebpf.sock.release %s : !ebpf.sock_ref", sk)
		one := l.constant(constant.MakeInt64(1), i8)
		l.emit("ebpf.yield %s, %s : i64, i8", a, one.name)
	})
	absent := l.region(func() {
		z := l.constant(constant.MakeInt64(0), i64)
		z8 := l.constant(constant.MakeInt64(0), i8)
		l.emit("ebpf.yield %s, %s : i64, i8", z.name, z8.name)
	})
	r := l.val()
	l.b.WriteString(l.indent + r + ":2 = ebpf.sock.ref_check " + sr + " : !ebpf.sock_ref_or_null -> i64, i8 present {\n" +
		l.indent + "^present(" + sk + ": !ebpf.sock_ref):\n" + present + l.indent + "} absent {\n" + absent + l.indent + "}" + l.locSuffix(call.Pos()) + "\n")
	results := []value{{r + "#0", i64}, l.fromCarrier(r+"#1", vtype{isBool: true})}
	for i, lhs := range s.Lhs {
		id, _ := lhs.(*ast.Ident)
		if id == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, lhs.Pos(), "assignment target must be a local variable")
			return true
		}
		if id.Name == "_" {
			continue
		}
		v := l.localVar(id, s.Tok == token.DEFINE)
		if v == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "assignment target %s must be a local variable", id.Name)
			return true
		}
		l.setVar(id, v, results[i])
	}
	return true
}

// skAssignPlace checks where Assign is placed (the body of an sk_lookup program, outside loops, with the program's context as the first argument).
func (l *lowerer) skAssignPlace(m *BpfMap, call *ast.CallExpr) bool {
	if l.progKind == nil || l.progKind.Kind != "sk_lookup" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.Assign selects a socket for an sk_lookup lookup — it may only be called in the body of an sk_lookup program (func f(ctx *bpf.SkLookupContext) bpf.SKAction)", m.Symbol)
		return false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.Assign cannot be called inside a loop (bpf-mlir allows sock.map_lookup only in the program body and its if / sock.ref_check arms)", m.Symbol)
		return false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s.Assign must be the program's context parameter", m.Symbol)
		return false
	}
	return true
}
