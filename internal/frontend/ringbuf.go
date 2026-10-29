package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/types"
)

// Ring buffers.
//
//	var Events = bpf.RingBuf[Event]{MaxEntries: 1 << 16}
//	_ = Events.Output(Event{…})                       → ringbuf.reserve → if_reserved { record.make → store_record → submit } absent { }
//	Events.Output(Event{…}, bpf.CountDropsIn(D, k))  → map.atomic_add %D[k], 1 in the absent region (allowed as a statement — D holds the drop count)
//	ok := Events.Output(Event{…})                     → %ok = if_reserved … -> i8 { … submit; yield 1 } absent { yield 0 }
//	Events.Output(Event{…})                           → GB017 (discards the result and counts no drops — make it explicit with `_ =`)
//
// The reservation is never exposed as a Go value, so submit happens exactly once (linearity by structure). The result is whether the reservation succeeded (the result of bpf-mlir's if_reserved).

// ringbufMinBytes is the frontend's conservative lower bound (the x86_64 page size — the kernel needs a multiple of the page size and a power of 2).
const ringbufMinBytes = 4096

// ringbufRecordLen returns the bytes an event of the given size occupies in the ring (with the 8-byte header, rounded up to 8 — the len of
// __bpf_ringbuf_reserve in kernel/bpf/ringbuf.c).
func ringbufRecordLen(size uint64) uint64 { return (size + 8 + 7) &^ 7 }

// ringbufFits reports whether an event of the given size can be reserved in an empty ring (measured). The kernel refuses on len > total_data_sz and
// new_prod_pos - cons_pos > mask, and on an empty ring the latter (len > n - 1) is stricter. n is a multiple of 8, so this equals size <= n - 16.
func ringbufFits(size, n uint64) bool { return ringbufRecordLen(size) <= n-1 }

// checkRingbufFit is the switch for the ringbufFits check — only tests turn it off (to pass the .mlir generated without it to ebpf-compile and confirm that bpf-mlir's
// ebpf-verify-schema stops at the same boundary). Production builds always check (TestCheckSwitchesTestOnly).
var checkRingbufFit = true

// ringbufInstance returns V if t is an instance of bpf.RingBuf[V].
func ringbufInstance(t types.Type) (types.Type, bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg || n.Origin().Obj().Name() != "RingBuf" {
		return nil, false
	}
	args := n.TypeArgs()
	if args == nil || args.Len() != 1 {
		return nil, false
	}
	return args.At(0), true
}

// collectRingBuf checks and collects ring buffer declarations.
func (a *analyzer) collectRingBuf(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, v types.Type) {
	m := &BpfMap{Symbol: obj.Name(), Kind: "ringbuf", Pos: a.position(name.Pos()), obj: obj}
	if _, isStruct := v.Underlying().(*types.Struct); !isStruct {
		a.report(Rejected, GB016SharedABIShape, name.Pos(), nil, "ring buffer %s: the event type must be a record (a named struct type declared in this package), got %s", obj.Name(), a.typeString(v))
		return
	}
	rv, ok := a.recordOf(v, name.Pos(), "ring buffer "+obj.Name()+" event")
	if !ok {
		return
	}
	m.Value = rv
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "ring buffer %s needs an initializer bpf.RingBuf[V]{MaxEntries: N} (MaxEntries is required)", obj.Name())
		return
	}
	if !a.mapInit(m, vs.Values[i]) {
		return
	}
	if n := m.MaxEntries; n < ringbufMinBytes || n&(n-1) != 0 {
		a.report(Rejected, GB009MapDeclShape, m.maxPos, nil, "ring buffer %s: MaxEntries (bytes) must be a power of two and a multiple of the x86_64 page size (4096), got %d", obj.Name(), n)
		return
	}
	if checkRingbufFit && !ringbufFits(rv.Size, m.MaxEntries) {
		need := ringbufRecordLen(rv.Size)
		grow := m.MaxEntries
		for !ringbufFits(rv.Size, grow) {
			grow *= 2
		}
		a.report(Rejected, GB009MapDeclShape, m.maxPos, nil, "ring buffer %s: event %s is %d bytes (%d with the 8-byte header, rounded up to 8), but a ring of %d bytes can reserve at most %d bytes per event (MaxEntries - 16: the kernel cannot reserve a record that fills the whole ring) — every Output would fail; raise MaxEntries to %d or shrink the event", obj.Name(), a.typeString(v), rv.Size, need, m.MaxEntries, m.MaxEntries-16, grow)
		return
	}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// argMaps returns the maps placed in a function's block arguments and maps [...] (ring buffers are referenced by name, so excluded — bpf-mlir's ringbuf.reserve "name").
func argMaps(ms []*BpfMap) []*BpfMap {
	var out []*BpfMap
	for _, m := range ms {
		if m.Kind != "ringbuf" && m.Kind != "user_ringbuf" { // user_ringbuf is also referenced by name (ebpf.user_ringbuf.drain "name")
			out = append(out, m)
		}
	}
	return out
}

// output lowers `R.Output(T{…} [, bpf.CountDropsIn(D, k)])`. withResult is the shape that uses the result (whether the reservation succeeded and was submitted — bool),
// where if_reserved returns i8 (1 in present, 0 in absent — a bool is carried as i8; the result of bpf-mlir's if_reserved).
// The shapes that do not use the result (a statement passing CountDropsIn, `_ =`) keep an if_reserved without a result (the same .mlir as before).
func (l *lowerer) output(call *ast.CallExpr, m *BpfMap, withResult bool) (value, bool) {
	if len(call.Args) < 1 || len(call.Args) > 2 || call.Ellipsis.IsValid() {
		l.fail(Rejected, GB001UnsupportedConstruct, call.Pos(), "%s.Output takes the event and at most one bpf.CountDropsIn(…)", m.Symbol)
		return value{}, false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.Output cannot be inside a loop (bpf-mlir does not allow ring buffer ops in a loop body)", m.Symbol)
		return value{}, false
	}
	var drops *BpfMap
	var dropKey value
	if len(call.Args) == 2 {
		var ok bool
		if drops, dropKey, ok = l.dropCounter(call.Args[1]); !ok {
			return value{}, false
		}
	}
	rt := m.Value.mlir()
	res := l.val()
	l.emit("%s = ebpf.ringbuf.reserve %q : !ebpf.maybe_reservation<%s>", res, m.Symbol, rt)
	borrow := l.val()
	var made string
	ok := true
	present := l.region(func() {
		l.commOK, l.commPaths = true, nil
		made, ok = l.recordMake(call.Args[0], m.Value)
		l.commOK = false
		if !ok {
			return
		}
		defer l.at(call.Pos())()
		l.emit("ebpf.ringbuf.store_record %s, %s : !ebpf.reservation<%s>, %s", borrow, made, rt, rt)
		for _, path := range l.commPaths {
			// a bpf.CurrentComm() field — the status is discarded (it fails only when current is NULL, and the field is 0 — see the bpf.CurrentComm doc).
			st := l.val()
			l.emit("%s = ebpf.task.comm %s %q : !ebpf.reservation<%s> -> i64", st, borrow, path, rt)
		}
		l.emit("ebpf.ringbuf.submit %s : !ebpf.reservation<%s>", borrow, rt)
		l.yieldFlag(withResult, 1)
	})
	if !ok {
		return value{}, false
	}
	absent := l.region(func() {
		defer l.at(call.Pos())()
		if drops != nil {
			one := l.constant(constant.MakeInt64(1), vtype{bits: 64})
			l.emit("ebpf.map.atomic_add %s[%s], %s : %s, %s, %s", l.mapArgs[drops], dropKey.name, one.name, l.mapType(drops), drops.Key.mlir(), drops.Value.mlir())
		}
		l.yieldFlag(withResult, 0)
	})
	lhs, result, r := "", "", ""
	if withResult {
		r = l.val()
		lhs, result = r+" = ", " -> i8"
	}
	l.b.WriteString(fmt.Sprintf("%s%sebpf.ringbuf.if_reserved %s : !ebpf.maybe_reservation<%s>%s present {\n%s^present(%s: !ebpf.reservation<%s>):\n%s%s} absent {\n%s%s}%s\n",
		l.indent, lhs, res, rt, result, l.indent, borrow, rt, present, l.indent, absent, l.indent, l.locSuffix(call.Pos())))
	if !withResult {
		return value{}, true
	}
	return l.fromCarrier(r, vtype{isBool: true}), true
}

// yieldFlag ends an if_reserved arm: the shape that uses the result yields v as i8, the other yields no value.
func (l *lowerer) yieldFlag(withResult bool, v int64) {
	if !withResult {
		l.emit("ebpf.yield")
		return
	}
	c := l.constant(constant.MakeInt64(v), vtype{bits: 8})
	l.emit("ebpf.yield %s : i8", c.name)
}

// dropCounter checks `bpf.CountDropsIn(D, k)`: D is an integer (u32 → u64) array map, k a constant below D's MaxEntries
// (an atomic_add on an out-of-range key fails its lookup and silently counts nothing). The key constant is made before if_reserved.
func (l *lowerer) dropCounter(e ast.Expr) (*BpfMap, value, bool) {
	call, isCall := e.(*ast.CallExpr)
	var obj types.Object
	if isCall {
		switch f := call.Fun.(type) {
		case *ast.SelectorExpr:
			obj = l.a.info.Uses[f.Sel]
		case *ast.Ident:
			obj = l.a.info.Uses[f]
		}
	}
	if en, known := lookupAPI(obj); !isCall || !known || en.op != "count_drops" || len(call.Args) != 2 {
		l.fail(Rejected, GB001UnsupportedConstruct, e.Pos(), "the second argument of Output must be written as bpf.CountDropsIn(<map>, <constant key>)")
		return nil, value{}, false
	}
	id, _ := call.Args[0].(*ast.Ident)
	var d *BpfMap
	if id != nil {
		v, _ := l.a.info.Uses[id].(*types.Var)
		d = l.a.mapByObj[v]
	}
	if d == nil || d.Kind != "array" {
		l.fail(Rejected, GB001UnsupportedConstruct, call.Args[0].Pos(), "bpf.CountDropsIn needs a package-level bpf.Array[uint32, uint64] map variable")
		return nil, value{}, false
	}
	tv := l.a.info.Types[call.Args[1]]
	if tv.Value == nil {
		l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the key of bpf.CountDropsIn must be a constant")
		return nil, value{}, false
	}
	k, exact := constant.Uint64Val(constant.ToInt(tv.Value))
	if !exact || k >= d.MaxEntries {
		l.fail(Rejected, GB009MapDeclShape, call.Args[1].Pos(), "the key %s of bpf.CountDropsIn is outside map %s (MaxEntries %d) — an atomic add on a missing key counts nothing", tv.Value.ExactString(), d.Symbol, d.MaxEntries)
		return nil, value{}, false
	}
	defer l.at(call.Pos())()
	return d, l.constant(tv.Value, vtypeOf(*d.Key.Int)), true
}

// isGobpfFunc reports whether call is a call of the gobpf package function name (including explicit type arguments `gobpf.NewReader[Event](…)`).
func (a *analyzer) isGobpfFunc(call *ast.CallExpr, name string) bool {
	fun := call.Fun
	if ix, ok := fun.(*ast.IndexExpr); ok {
		fun = ix.X
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj := a.info.Uses[sel.Sel]
	return obj != nil && obj.Pkg() != nil && obj.Pkg().Path() == gobpfPkg && obj.Name() == name
}
