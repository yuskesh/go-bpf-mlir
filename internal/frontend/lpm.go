package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// lpm_trie maps.
//
//	var Deny = bpf.LPMTrie4[uint32]{MaxEntries: 1024}
//	v, ok := Deny.Lookup([4]byte{w.U8(26), w.U8(27), w.U8(28), w.U8(29)})
//
// The key is the record gobpf_lpm_key4 {prefixlen: u32 @0, addr: u8[4] @4} owned by the bpf side (bpf-mlir's convention — Schema.cpp checks its name and shape),
// flags is BPF_F_NO_PREALLOC (1). The eBPF side only reads: Lookup returns the value and ok (not a pointer — a write through a borrow cannot be typed).
//
//	%k = ebpf.record.make ["prefixlen", "addr[0]", …] (%c32, %a0, …) -> !ebpf.record<"gobpf_lpm_key4", 8>
//	%m = ebpf.map.lookup Deny[%k]
//	%r:2 = ebpf.ref.check %m -> V, i8 present(%b) { %x = ebpf.ref.load %b; yield %x, 1 } absent { yield 0, 0 }
//
// The value is read with a single ref.load inside present (two reads could mix with a concurrent Put from user space).

const (
	lpmKeySymbol  = "gobpf_lpm_key4" // recordOf stops a user record with the gobpf_ prefix
	lpmKeyGoType  = "bpf.LPMKey4"
	lpmNoPrealloc = 1 // BPF_F_NO_PREALLOC
)

// lpmInstance returns V and the bpf package if t is an instance of bpf.LPMTrie4[V].
func lpmInstance(t types.Type) (v types.Type, bpf *types.Package, ok bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg || n.Origin().Obj().Name() != "LPMTrie4" {
		return nil, nil, false
	}
	args := n.TypeArgs()
	if args == nil || args.Len() != 1 {
		return nil, nil, false
	}
	return args.At(0), n.Origin().Obj().Pkg(), true
}

// lpmKeyABI is the key record (bpf.LPMKey4 — a fixed shape, bpf-mlir's convention as is). The position of the first LPMTrie4 declaration is its provenance position.
func (a *analyzer) lpmKeyABI(bpf *types.Package, at token.Position) SharedABI {
	if r, done := a.recordBySymbol[lpmKeySymbol]; done {
		return r
	}
	u32 := IntType{32, false}
	u8 := IntType{8, false}
	goT := bpf.Scope().Lookup("LPMKey4").Type()
	st := goT.Underlying().(*types.Struct)
	elem := sharedABIOfInt(types.Typ[types.Uint8], u8)
	rec := &RecordABI{Symbol: lpmKeySymbol, GoExpr: lpmKeyGoType, Pos: at, Fields: []FieldABI{
		{Name: "prefixlen", GoName: st.Field(0).Name(), Offset: 0, Type: sharedABIOfInt(types.Typ[types.Uint32], u32)},
		{Name: "addr", GoName: st.Field(1).Name(), Offset: 4, Type: SharedABI{Kind: ABIArray, GoType: st.Field(1).Type(), Size: 4, Align: 1, Array: &ArrayABI{Count: 4, Elem: elem}}},
	}}
	abi := SharedABI{Kind: ABIRecord, GoType: goT, Size: 8, Align: 4, Record: rec}
	a.recordBySymbol[lpmKeySymbol] = abi
	a.records = append(a.records, &abi)
	return abi
}

// collectLPM checks and collects LPMTrie4 declarations (V's width is the bpf.LPMValue constraint — Go's type check stops anything but 32 / 64 bit).
func (a *analyzer) collectLPM(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, v types.Type, bpf *types.Package) {
	m := &BpfMap{Symbol: obj.Name(), Kind: "lpm_trie", Flags: lpmNoPrealloc, Pos: a.position(name.Pos()), obj: obj}
	vi, ok := intTypeOf(v)
	if !ok || vi.Bits < 32 {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s: the value of a bpf.LPMTrie4 must be a 32 or 64 bit integer, got %s", obj.Name(), a.typeString(v))
		return
	}
	m.Value = sharedABIOfInt(v, vi)
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s needs an initializer bpf.LPMTrie4[V]{MaxEntries: N} (MaxEntries is required)", obj.Name())
		return
	}
	if !a.mapInit(m, vs.Values[i]) {
		return
	}
	m.Key = a.lpmKeyABI(bpf, m.Pos)
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// isLPMLookup reports whether call is LPMTrie4.Lookup.
func (l *lowerer) isLPMLookup(call ast.Expr) (*ast.CallExpr, bool) {
	c, ok := call.(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	_, e, _, known := l.mapMethod(c)
	return c, known && e.op == "lpm_lookup"
}

// lpmLookupAssign lowers `v, ok := M.Lookup(a)` / `v, ok = M.Lookup(a)` (`_` allowed in either).
func (l *lowerer) lpmLookupAssign(s *ast.AssignStmt, call *ast.CallExpr) {
	defer l.at(call.Pos())()
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
		return
	}
	m, _, _, _ := l.mapMethod(call)
	vt := vtypeOf(*m.Value.Int)
	k, ok := l.lpmKey(m, call.Args[0])
	if !ok {
		return
	}
	mt := l.mapType(m)
	ref := l.val()
	l.emit("%s = ebpf.map.lookup %s[%s] : %s, %s -> !ebpf.maybe_ref<%s>", ref, l.mapArgs[m], k, mt, m.Key.mlir(), m.Value.mlir())
	borrow := l.val()
	i8 := vtype{bits: 8}
	present := l.region(func() {
		x := l.val()
		l.emit("%s = ebpf.ref.load %s : !ebpf.borrowed<%s> -> %s", x, borrow, vt.mlir(), vt.mlir())
		one := l.constant(constant.MakeInt64(1), i8)
		l.emit("ebpf.yield %s, %s : %s, i8", x, one.name, vt.mlir())
	})
	absent := l.region(func() {
		z := l.constant(constant.MakeInt64(0), vt)
		z8 := l.constant(constant.MakeInt64(0), i8)
		l.emit("ebpf.yield %s, %s : %s, i8", z.name, z8.name, vt.mlir())
	})
	r := l.val()
	l.b.WriteString(l.indent + r + ":2 = ebpf.ref.check " + ref + " : !ebpf.maybe_ref<" + vt.mlir() + "> -> " + vt.mlir() + ", i8 present {\n" +
		l.indent + "^present(" + borrow + ": !ebpf.borrowed<" + vt.mlir() + ">):\n" + present + l.indent + "} absent {\n" + absent + l.indent + "}" + l.locSuffix(call.Pos()) + "\n")
	results := []value{{r + "#0", vt}, l.fromCarrier(r+"#1", vtype{isBool: true})}
	for i, lhs := range s.Lhs {
		id, _ := lhs.(*ast.Ident)
		if id == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, lhs.Pos(), "assignment target must be a local variable")
			return
		}
		if id.Name == "_" {
			continue
		}
		v := l.localVar(id, s.Tok == token.DEFINE)
		if v == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "assignment target %s must be a local variable", id.Name)
			return
		}
		l.setVar(id, v, results[i])
	}
}

// lpmKey lowers the Lookup argument (a `[4]byte{a, b, c, d}` composite literal — 4 bytes in network order) to the key's record.make (prefixlen 32).
func (l *lowerer) lpmKey(m *BpfMap, e ast.Expr) (string, bool) {
	cl, ok := e.(*ast.CompositeLit)
	if !ok || len(cl.Elts) != 4 {
		l.fail(Rejected, GB001UnsupportedConstruct, e.Pos(), "the address of %s.Lookup must be written as an array literal of its 4 bytes in network order (`[4]byte{a, b, c, d}`)", m.Symbol)
		return "", false
	}
	u8 := vtype{bits: 8}
	i32 := vtype{bits: 32}
	plen := l.constant(constant.MakeInt64(32), i32)
	paths := []string{`"prefixlen"`}
	names := []string{plen.name}
	typs := []string{"i32"}
	for i, el := range cl.Elts {
		if _, isKV := el.(*ast.KeyValueExpr); isKV {
			l.fail(Rejected, GB001UnsupportedConstruct, el.Pos(), "indexed elements in the address literal are not supported; list the 4 bytes in order")
			return "", false
		}
		v, ok := l.expr(el, &u8)
		if !ok {
			return "", false
		}
		paths = append(paths, `"`+indexPath("addr", uint64(i))+`"`)
		names = append(names, v.name)
		typs = append(typs, "i8")
	}
	r := l.val()
	l.emit("%s = ebpf.record.make [%s] (%s) : (%s) -> %s", r, strings.Join(paths, ", "), strings.Join(names, ", "), strings.Join(typs, ", "), m.Key.mlir())
	return r, true
}
