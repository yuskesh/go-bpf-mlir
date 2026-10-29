package frontend

import (
	"go/ast"
	"go/constant"
	"go/types"
)

// Hash-family maps.
//
//	var Flows = bpf.Hash[FlowKey, uint64]{MaxEntries: 4096}
//	st := Flows.Insert(FlowKey{…}, 1)   → map.try_update flags "noexist" (an int64 status)
//	st := Flows.Delete(FlowKey{…})      → map.try_delete
//	if p := Flows.Lookup(FlowKey{…}); p != nil { … }
//
// Operations return a status, and an expression statement that discards it is GB017 (an explicit `_ =` is accepted). A record key is a composite literal (record.make).

// hashInstance returns the schema kind, K and V if t is an instance of bpf.Hash[K, V] / bpf.LRUHash[K, V].
func hashInstance(t types.Type) (kind string, k, v types.Type, ok bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg {
		return "", nil, nil, false
	}
	switch n.Origin().Obj().Name() {
	case "Hash":
		kind = "hash"
	case "LRUHash":
		kind = "lru_hash"
	case "PerCPUHash":
		kind = "percpu_hash"
	case "LRUPerCPUHash":
		kind = "lru_percpu_hash"
	default:
		return "", nil, nil, false
	}
	args := n.TypeArgs()
	if args == nil || args.Len() != 2 {
		return "", nil, nil, false
	}
	return kind, args.At(0), args.At(1), true
}

// sharedKeyOrValue turns a hash-family K / V into a SharedABI: a 32 / 64-bit integer or a record (the shared-type rules).
func (a *analyzer) sharedKeyOrValue(t types.Type, name *ast.Ident, what string) (SharedABI, bool) {
	if it, ok := intTypeOf(t); ok {
		if it.Bits < 32 {
			a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s: an integer %s must be 32 or 64 bit, got %s (wrap narrower values in a record)", name.Name, what, a.typeString(t))
			return SharedABI{}, false
		}
		return sharedABIOfInt(t, it), true
	}
	return a.recordOf(t, name.Pos(), "map "+name.Name+" "+what)
}

// collectHash checks and collects hash-family map declarations.
func (a *analyzer) collectHash(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, kind string, k, v types.Type) {
	m := &BpfMap{Symbol: obj.Name(), Kind: kind, Pos: a.position(name.Pos()), obj: obj}
	var ok bool
	if m.Key, ok = a.sharedKeyOrValue(k, name, "key"); !ok {
		return
	}
	if m.Value, ok = a.sharedKeyOrValue(v, name, "value"); !ok {
		return
	}
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s needs an initializer with MaxEntries (MaxEntries is required)", obj.Name())
		return
	}
	if !a.mapInit(m, vs.Values[i]) {
		return
	}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

func isHashKind(kind string) bool {
	return kind == "hash" || kind == "lru_hash" || kind == "percpu_hash" || kind == "lru_percpu_hash"
}

// isArrayKind reports whether kind is an array-family kind (ranged keys — subject to the out-of-range check of constant keys and the proof of variable keys; includes percpu_array).
func isArrayKind(kind string) bool { return kind == "array" || kind == "percpu_array" }

// mapKey turns the key expression of a map operation into an SSA value name: an integer is the expression, a record is a record.make of the composite literal.
// A constant Array key ≥ MaxEntries is GB009 (the kernel silently does nothing for an out-of-range key — a review point).
func (l *lowerer) mapKey(m *BpfMap, e ast.Expr) (string, bool) {
	switch m.Key.Kind {
	case ABIRecord:
		return l.recordMake(e, m.Key)
	case ABIInt:
		if isArrayKind(m.Kind) && l.a.info.Types[e].Value == nil {
			l.proveArrayKey(m, e) // a variable key — a proof or a Conditional diagnostic
		}
		if isArrayKind(m.Kind) {
			if tv := l.a.info.Types[e]; tv.Value != nil {
				if n, exact := constant.Uint64Val(constant.ToInt(tv.Value)); exact && n >= m.MaxEntries {
					l.fail(Rejected, GB009MapDeclShape, e.Pos(), "the key %s is outside map %s (MaxEntries %d) — the kernel does nothing for an out-of-range array key", tv.Value.ExactString(), m.Symbol, m.MaxEntries)
					return "", false
				}
			}
		}
		t := vtypeOf(*m.Key.Int)
		v, ok := l.expr(e, &t)
		return v.name, ok
	}
	l.fail(Unknown, GB016SharedABIShape, e.Pos(), "map %s: unsupported key shape", m.Symbol)
	return "", false
}

// mapValue turns a map value expression into an SSA value name (an integer is the expression, a record is a composite literal).
func (l *lowerer) mapValue(m *BpfMap, e ast.Expr) (string, bool) {
	if m.Value.Kind == ABIRecord {
		return l.recordMake(e, m.Value)
	}
	t := vtypeOf(*m.Value.Int)
	v, ok := l.expr(e, &t)
	return v.name, ok
}

// statusCall lowers a status-returning hash-family operation (Update / Insert / Replace / Delete) as an expression.
func (l *lowerer) statusCall(call *ast.CallExpr, m *BpfMap, e apiEntry) (value, bool) {
	if e.op == "add_or_init" {
		return l.addOrInit(call, m)
	}
	if e.op == "storage_delete" {
		return l.storageDelete(call, m)
	}
	if e.op == "keyless_push" || e.op == "bloom_push" || e.op == "bloom_peek" {
		return l.keylessStatus(call, m, e)
	}
	if e.op == "sock_insert" {
		return l.sockInsert(call, m)
	}
	if e.op == "reuseport_select" {
		return l.reuseportSelect(call, m)
	}
	if e.op == "cgarr_task" || e.op == "cgarr_skb" {
		return l.cgarrUnder(call, m, e.op)
	}
	defer l.at(call.Pos())()
	k, ok := l.mapKey(m, call.Args[0])
	if !ok {
		return value{}, false
	}
	st := vtype{bits: 64, signed: true}
	r := l.val()
	if e.op == "try_delete" {
		l.emit("%s = ebpf.map.try_delete %s[%s] : %s, %s -> i64", r, l.mapArgs[m], k, l.mapType(m), m.Key.mlir())
		return value{r, st}, true
	}
	v, ok := l.mapValue(m, call.Args[1])
	if !ok {
		return value{}, false
	}
	l.emit("%s = ebpf.map.try_update %s[%s], %s flags %q : %s, %s, %s -> i64", r, l.mapArgs[m], k, v, statusOps[e.op], l.mapType(m), m.Key.mlir(), m.Value.mlir())
	return value{r, st}, true
}

// addOrInit lowers `M.AddOrInit(k, d)` (the result is an i64 status):
//
//	%m = map.lookup M[k]
//	%st = ref.check %m -> i64 present(%r) { ref.atomic_add %r, d; yield 0 }
//	                          absent { %s1 = try_update M[k], d flags "noexist"
//	                                   %res = if (%s1 == -EEXIST) -> i64 { %m2 = map.lookup M[k]
//	                                                                       %s2 = ref.check %m2 -> i64 present(%r2) { ref.atomic_add %r2, d; yield 0 } absent { yield -ENOENT }
//	                                                                       if.yield %s2 }
//	                                                        else { if.yield %s1 }
//	                                   yield %res }
//
// The key's record.make is emitted once and used by the lookup / try_update in nested regions (following bpf-mlir's kernel/flow).
func (l *lowerer) addOrInit(call *ast.CallExpr, m *BpfMap) (value, bool) {
	defer l.at(call.Pos())()
	if m.Value.Kind != ABIInt {
		l.fail(Rejected, GB016SharedABIShape, call.Pos(), "%s.AddOrInit needs an integer value, but %s holds the record %s — ebpf.ref.atomic_add adds only to an integer (a record field's += is not atomic)", m.Symbol, m.Symbol, m.Value.Record.Symbol)
		return value{}, false
	}
	k, ok := l.mapKey(m, call.Args[0])
	if !ok {
		return value{}, false
	}
	d, ok := l.mapValue(m, call.Args[1])
	if !ok {
		return value{}, false
	}
	mt, kt, vt := l.mapType(m), m.Key.mlir(), m.Value.mlir()
	i64 := vtype{bits: 64, signed: true}
	// lookupAdd emits lookup → ref.check (present: atomically add d and yield 0; absent: the i64 that absent() yields) and returns the result name.
	lookupAdd := func(absent func()) string {
		mr := l.val()
		l.emit("%s = ebpf.map.lookup %s[%s] : %s, %s -> !ebpf.maybe_ref<%s>", mr, l.mapArgs[m], k, mt, kt, vt)
		r := l.val()
		present := l.region(func() {
			l.emit("ebpf.ref.atomic_add %s, %s : !ebpf.borrowed<%s>, %s", r, d, vt, vt)
			z := l.constant(constant.MakeInt64(0), i64)
			l.emit("ebpf.yield %s : i64", z.name)
		})
		abs := l.region(absent)
		st := l.val()
		l.b.WriteString(l.indent + st + " = ebpf.ref.check " + mr + " : !ebpf.maybe_ref<" + vt + "> -> i64 present {\n" +
			l.indent + "^present(" + r + ": !ebpf.borrowed<" + vt + ">):\n" + present + l.indent + "} absent {\n" + abs + l.indent + "}" + l.locSuffix(call.Pos()) + "\n")
		return st
	}
	st := lookupAdd(func() {
		s1 := l.val()
		l.emit("%s = ebpf.map.try_update %s[%s], %s flags \"noexist\" : %s, %s, %s -> i64", s1, l.mapArgs[m], k, d, mt, kt, vt)
		ee := l.constant(constant.MakeInt64(-errEEXIST), i64)
		is := l.val()
		l.emit("%s = arith.cmpi eq, %s, %s : i64", is, s1, ee.name)
		then := l.region(func() {
			// Another CPU created it first — look it up again and add. A second absent (deleted right after creation) is a synthesized -ENOENT.
			s2 := lookupAdd(func() {
				c := l.constant(constant.MakeInt64(-errENOENT), i64) // synthesized by AddOrInit
				l.emit("ebpf.yield %s : i64", c.name)
			})
			l.emit("ebpf.if.yield %s : i64", s2)
		})
		els := l.region(func() { l.emit("ebpf.if.yield %s : i64", s1) })
		res := l.val()
		l.b.WriteString(l.indent + res + " = ebpf.if " + is + " -> i64 {\n" + then + l.indent + "} else {\n" + els + l.indent + "}" + l.locSuffix(call.Pos()) + "\n")
		l.emit("ebpf.yield %s : i64", res)
	})
	return value{st, i64}, true
}

// Linux errno values used by the AddOrInit lowering (the same values as bpf.EEXIST / bpf.ENOENT — a test checks them against unix).
const (
	errENOENT = 2
	errEEXIST = 17
)
