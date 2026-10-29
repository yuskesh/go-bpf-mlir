package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"regexp"
)

// struct_ops tcp_congestion_ops (bpf-mlir's map kind struct_ops and program kind struct_ops):
//
//	var CC = bpf.TCPCongestionOps{Name: "gobpf_cc"}   → the schema map {kind: struct_ops, struct_ops: {type, name, ops: [{member, program}]}}
//	//gobpf:struct_ops CC init                         → ebpf.program @f "struct_ops" attach "CC" (the map CC is not put in the program's maps)
//
// bpf-mlir has no table of member signatures (the schema's nargs / ret are checked by retsig at load time) and does not check required members. go
// checks the Go shape statically with **a member table** (the Go result type and nargs — 4 members with the same signature in include/net/tcp.h on all three kernels), and names a missing
// required member before the −EINVAL of the kernel's tcp_validate_congestion_control (net/ipv4/tcp_cong.c — ssthresh, undo_cwnd, cong_avoid or cong_control).
// cong_control is not in the table because its signature differs on 6.6.

// structOpsMember is the signature of a tcp_congestion_ops member (the kernel's include/net/tcp.h — the same at 7.1.8 line 1316, 6.12 line 1142, 6.6 line 1058).
type structOpsMember struct {
	nargs    int
	ret      *IntType // nil is void
	required bool
	args     []string // the type of argument i — "sock" (struct sock * — the verifier promotes it to tcp_sock: the local type tag is tcp_sock) or "u32"
}

var u32Type = IntType{Bits: 32}

// tcpCongestionMembers are the tcp_congestion_ops members go accepts (the 3 required ones and init).
var tcpCongestionMembers = map[string]structOpsMember{
	"init":       {nargs: 1, args: []string{"sock"}},
	"ssthresh":   {nargs: 1, ret: &u32Type, required: true, args: []string{"sock"}},
	"undo_cwnd":  {nargs: 1, ret: &u32Type, required: true, args: []string{"sock"}},
	"cong_avoid": {nargs: 3, required: true, args: []string{"sock", "u32", "u32"}},
}

// structOpsPromoted maps the BTF type of a member's struct argument to the promoted type the program reads (PROMOTION in bpf-mlir's StructOpsTypes.def — for tcp_congestion_ops
// sock → tcp_sock; the farg requirement is mapped back to the BTF sock).
var structOpsPromoted = map[string]string{"sock": "tcp_sock"}

// structOpsArgOK checks a read of argument i of a struct_ops program against the member table. kt is the local type of StructOpsArg (nil for an integer read),
// it the type of StructOpsArgInt. Errors are GB027 at pos.
func (l *lowerer) structOpsArgOK(pos token.Pos, i int, kt *KernelType, it *IntType) bool {
	mem, ok := tcpCongestionMembers[l.prog.SOMember]
	if !ok {
		l.failed = true // the member error is already reported
		return false
	}
	if i >= len(mem.args) {
		l.fail(Rejected, GB027KernelTypeShape, pos, "the tcp_congestion_ops member %s takes %d argument(s) — index %d is outside", l.prog.SOMember, len(mem.args), i)
		return false
	}
	want := mem.args[i]
	switch {
	case kt != nil && want != "sock":
		l.fail(Rejected, GB027KernelTypeShape, pos, "argument %d of the tcp_congestion_ops member %s is a %s integer — read it with bpf.StructOpsArgInt[uint32](ctx, %d)", i, l.prog.SOMember, want, i)
		return false
	case kt != nil && kt.Name != structOpsPromoted[want]:
		l.fail(Rejected, GB027KernelTypeShape, pos, "argument %d of the tcp_congestion_ops member %s is struct sock * (the verifier promotes it to tcp_sock) — the local type must be `kernel:\"tcp_sock\"`, got %s", i, l.prog.SOMember, kt.Name)
		return false
	case it != nil && want == "sock":
		l.fail(Rejected, GB027KernelTypeShape, pos, "argument %d of the tcp_congestion_ops member %s is struct sock * — read it with `if sk := bpf.StructOpsArg[T](ctx, %d); sk != nil { … }`", i, l.prog.SOMember, i)
		return false
	case it != nil && (it.Bits != 32 || it.Signed):
		l.fail(Rejected, GB027KernelTypeShape, pos, "argument %d of the tcp_congestion_ops member %s is u32 — the type argument of bpf.StructOpsArgInt must be uint32, got %s", i, l.prog.SOMember, it.mlir())
		return false
	}
	return true
}

// kptrStore lowers `sk.F = v` of a struct_ops program (sk a checked kernel pointer, F an integer field) to ebpf.kfield.store.
// handled reports whether s has that shape.
func (l *lowerer) kptrStore(s *ast.AssignStmt) bool {
	if s.Tok != token.ASSIGN || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	if sel, ok := ast.Unparen(s.Lhs[0]).(*ast.SelectorExpr); ok {
		if call, isCall := ast.Unparen(sel.X).(*ast.CallExpr); isCall && l.callOp(call) == "structops_arg" {
			l.fail(Rejected, GB005NilCheckShape, call.Pos(), "bpf.StructOpsArg returns a pointer that may be NULL — write its fields only inside `if sk := bpf.StructOpsArg[T](ctx, 0); sk != nil { sk.F = v }`")
			return true
		}
	}
	kp, f, sel, handled := l.kptrSel(s.Lhs[0])
	if !handled {
		return false
	}
	if f == nil {
		return true
	}
	if l.progKind == nil || l.progKind.Kind != "struct_ops" {
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel struct field %s cannot be written — only a struct_ops program writes kernel fields", types.ExprString(sel))
		return true
	}
	if _, sels, _ := l.kpathOf(s.Lhs[0]); len(sels) > 1 { // checkKptrUses reports it first; bpf-mlir's kfield.store takes one segment
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel struct field path %s cannot be written — a struct_ops program writes only a field of the argument itself", types.ExprString(sel))
		return true
	}
	if f.Kind != kfInt {
		l.fail(Rejected, GB027KernelTypeShape, sel.Pos(), "the kernel struct field %s is not an integer — a struct_ops program writes integer fields only (ebpf.kfield.store)", types.ExprString(sel))
		return true
	}
	it := IntType{Bits: f.Bits, Signed: f.Signed}
	want := vtypeOf(it)
	v, ok := l.expr(s.Rhs[0], &want)
	if !ok {
		return true
	}
	defer l.at(s.Pos())()
	l.emit("ebpf.kfield.store %s %q, %s : !ebpf.kptr<%q>, %s", kp.name, f.Name, v.name, kp.kt.Name, it.mlir())
	return true
}

// tcpCongestionOrder is the order of required member diagnostics and of the schema's ops (a fixed order, not the struct declaration order — reproducible generated files).
var tcpCongestionOrder = []string{"init", "ssthresh", "cong_avoid", "undo_cwnd"}

// structOpsName matches the registration name (1 to 15 characters — TCP_CA_NAME_MAX 16 minus the terminator, the same characters as bpf-mlir's Schema.cpp).
var structOpsName = regexp.MustCompile(`^[A-Za-z0-9_.]{1,15}$`)

// StructOpsDecl is a struct_ops map declaration (the schema's struct_ops).
type StructOpsDecl struct {
	Type string
	Name string
	Ops  []StructOpsOp
}

// StructOpsOp is a pair of member and program.
type StructOpsOp struct {
	Member  string
	Program string
}

// collectStructOps turns `var CC = bpf.TCPCongestionOps{Name: "<name>"}` into a struct_ops map (key u32, max_entries 1, no value).
func (a *analyzer) collectStructOps(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int) {
	bad := func(at token.Pos, format string, args ...any) {
		a.report(Rejected, GB009MapDeclShape, at, nil, format, args...)
	}
	if len(vs.Values) != len(vs.Names) {
		bad(name.Pos(), "struct_ops %s needs an initializer bpf.TCPCongestionOps{Name: \"<name>\"}", obj.Name())
		return
	}
	cl, ok := vs.Values[i].(*ast.CompositeLit)
	if !ok {
		bad(vs.Values[i].Pos(), "struct_ops %s: the initializer must be a composite literal bpf.TCPCongestionOps{Name: \"<name>\"}", obj.Name())
		return
	}
	regName, at := "", vs.Values[i].Pos()
	for _, el := range cl.Elts {
		kv, isKV := el.(*ast.KeyValueExpr)
		if !isKV {
			bad(el.Pos(), "struct_ops %s: write the field by name (Name: \"<name>\")", obj.Name())
			return
		}
		if id, _ := kv.Key.(*ast.Ident); id == nil || id.Name != "Name" {
			bad(el.Pos(), "struct_ops %s: bpf.TCPCongestionOps has only the field Name", obj.Name())
			return
		}
		tv := a.info.Types[kv.Value]
		if tv.Value == nil || tv.Value.Kind() != constant.String {
			bad(kv.Value.Pos(), "struct_ops %s: Name must be a constant string", obj.Name())
			return
		}
		regName, at = constant.StringVal(tv.Value), kv.Value.Pos()
	}
	if !structOpsName.MatchString(regName) {
		// report but still register the map (generation stops — avoids a chained "no such map" error from the directive).
		bad(at, "struct_ops %s: Name %q must be 1 to 15 characters of [A-Za-z0-9_.] (the kernel's TCP_CA_NAME_MAX is 16 with the terminator, and setsockopt TCP_CONGESTION copies at most 15)", obj.Name(), regName)
	}
	for _, m := range a.maps {
		if m.Kind == "struct_ops" {
			bad(name.Pos(), "struct_ops %s: this package already declares the struct_ops map %s — one struct_ops map per package (cilium matches the programs of two maps of the same type by member name)", obj.Name(), m.Symbol)
			return
		}
	}
	u32 := types.Typ[types.Uint32]
	m := &BpfMap{Symbol: obj.Name(), Kind: "struct_ops", Pos: a.position(name.Pos()), obj: obj, Key: sharedABIOfInt(u32, IntType{32, false}), MaxEntries: 1,
		StructOps: &StructOpsDecl{Type: "tcp_congestion_ops", Name: regName}}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// structOpsDirective checks `//gobpf:struct_ops <map> <member>` and returns the map name as the attach (the member goes to a.soMemberOf).
func (a *analyzer) structOpsDirective(fd *ast.FuncDecl, at token.Pos, fields []string) (string, int, bool) {
	if len(fields) != 2 || !cIdent.MatchString(fields[0]) {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:struct_ops takes the struct_ops map variable and the member (`%s`), got %v", directiveUsage("struct_ops"), fields)
		return "", 0, false
	}
	var sm *BpfMap
	for _, m := range a.maps {
		if m.Symbol == fields[0] {
			sm = m
		}
	}
	if sm == nil || sm.Kind != "struct_ops" {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:struct_ops %s %s: %s is not a bpf.TCPCongestionOps variable of this package", fields[0], fields[1], fields[0])
		return "", 0, false
	}
	mem, known := tcpCongestionMembers[fields[1]]
	if !known {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:struct_ops %s %s: go supports the tcp_congestion_ops members init, ssthresh, undo_cwnd and cong_avoid only (cong_control has a different signature on 6.6)", fields[0], fields[1])
		return "", 0, false
	}
	a.soSeen[fields[0]+"/"+fields[1]] = true // the member was written even with a signature error (no chained missing-member error in checkStructOps)
	sig := a.info.Defs[fd.Name].(*types.Func).Type().(*types.Signature)
	gotRet := sig.Results().Len() == 1
	retOK := (mem.ret == nil && sig.Results().Len() == 0) || (mem.ret != nil && gotRet && types.Identical(sig.Results().At(0).Type(), types.Typ[types.Uint32]))
	if !retOK {
		want := "no result"
		if mem.ret != nil {
			want = "uint32"
		}
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:struct_ops %s %s: the member %s returns %s in tcp_congestion_ops — %s has %s", fields[0], fields[1], fields[1], want, fd.Name.Name, sig.Results())
		return "", 0, false
	}
	a.soMemberOf[fd] = fields[1]
	return fields[0], mem.nargs, true
}

// checkStructOps checks the member set of a struct_ops map: two programs for the same member, a missing required member.
// Errors are GB009 at the map declaration position. Programs are in package declaration order, the schema's ops in tcpCongestionOrder.
func (a *analyzer) checkStructOps() {
	for _, m := range a.maps {
		if m.Kind != "struct_ops" {
			continue
		}
		at := a.mapPos(m)
		byMember := map[string]string{}
		for _, p := range a.programs {
			if p.ProgramType != "struct_ops" || p.Attach != m.Symbol || p.SOMember == "" {
				continue
			}
			if prev, dup := byMember[p.SOMember]; dup {
				a.report(Rejected, GB009MapDeclShape, at, nil, "struct_ops %s: the member %s is implemented twice (%s and %s) — one program per member", m.Symbol, p.SOMember, prev, p.Symbol)
				return
			}
			byMember[p.SOMember] = p.Symbol
		}
		var missing []string
		for _, mem := range tcpCongestionOrder {
			if tcpCongestionMembers[mem].required && byMember[mem] == "" && !a.soSeen[m.Symbol+"/"+mem] {
				missing = append(missing, mem)
			}
		}
		if len(missing) > 0 {
			a.report(Rejected, GB009MapDeclShape, at, nil, "struct_ops %s: tcp_congestion_ops needs the members ssthresh, undo_cwnd and cong_avoid — missing %v (the kernel's tcp_validate_congestion_control rejects it with EINVAL at registration)", m.Symbol, missing)
			continue
		}
		m.StructOps.Ops = nil
		for _, mem := range tcpCongestionOrder {
			if prog := byMember[mem]; prog != "" {
				m.StructOps.Ops = append(m.StructOps.Ops, StructOpsOp{Member: mem, Program: prog})
			}
		}
	}
}

// mapPos returns the position of a map declaration (for diagnostics).
func (a *analyzer) mapPos(m *BpfMap) token.Pos {
	if m.obj != nil {
		return m.obj.Pos()
	}
	return token.NoPos
}

// structOpsKind picks the program kind row by the member's result (void is done without a result, uint32 is ebpf.return of the computed value).
func structOpsKind(base *ctxKind, mem structOpsMember) *ctxKind {
	k := *base
	if mem.ret != nil {
		k.Action, k.IntRet, k.IntRetExpr = "StructOpsRet", &fmodRetRange, true
	}
	return &k
}

// schemaStructOps returns the schema value of a struct_ops map (the struct_ops key of bpf-mlir's Schema.cpp).
type schemaStructOps struct {
	Type string           `json:"type"`
	Name string           `json:"name"`
	Ops  []schemaStructOp `json:"ops"`
}

type schemaStructOp struct {
	Member  string `json:"member"`
	Program string `json:"program"`
}
