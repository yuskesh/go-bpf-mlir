package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// Keyless maps (bpf-mlir v1.11.0's feature path F59):
//
//	var Q = bpf.Queue[uint32]{MaxEntries: 4}
//	st := Q.Push(v, bpf.PushAny)   → %st = ebpf.map.push %Q, %v flags "any" : !ebpf.map<"queue", none, i32>, i32 -> i64
//	v, st := Q.Pop()               → %r:2 = ebpf.map.pop %Q : !ebpf.map<"queue", none, i32> -> i64, i32   (#0 is the status, #1 the value)
//	v, st := Q.Peek()              → ebpf.map.peek
//	var B = bpf.BloomFilter[uint32]{MaxEntries: 16, ZeroSeed: true}
//	st := B.Push(v)                → ebpf.map.push %B, %v flags "any" : !ebpf.map<"bloom_filter", none, i32>, i32 -> i64
//	st := B.Peek(v)                → ebpf.bloom.peek %B, %v : … -> i64
//
// The operations cannot be placed in a loop body (they are not among the ops bpf-mlir's ebpf.loop body allows — GB018). A statement that discards the status is GB017.

// keylessKinds maps a bpf type name to the schema kind.
var keylessKinds = map[string]string{"Queue": "queue", "Stack": "stack", "BloomFilter": "bloom_filter"}

// isKeylessKind reports whether kind is a keyless map kind (the mlir key is none, and the schema has no key).
func isKeylessKind(kind string) bool {
	return kind == "queue" || kind == "stack" || kind == "bloom_filter"
}

// keylessInstance returns the kind and V if t is an instance of a bpf keyless map.
func keylessInstance(t types.Type) (kind string, v types.Type, ok bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg {
		return "", nil, false
	}
	k, known := keylessKinds[n.Origin().Obj().Name()]
	if !known || n.TypeArgs().Len() != 1 {
		return "", nil, false
	}
	return k, n.TypeArgs().At(0), true
}

// bpfZeroSeed is BPF_F_ZERO_SEED (sets the bloom hash seed to 0).
const bpfZeroSeed = 64

// collectKeyless checks and collects keyless map declarations (`bpf.Queue[V]{MaxEntries: N}`, `bpf.BloomFilter[V]{MaxEntries: N, ZeroSeed: true}`).
func (a *analyzer) collectKeyless(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, kind string, v types.Type) {
	m := &BpfMap{Symbol: obj.Name(), Kind: kind, Pos: a.position(name.Pos()), obj: obj}
	vi, ok := intTypeOf(v)
	if !ok {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s: the value of a %s map must be an 8 / 16 / 32 / 64-bit integer, got %s", obj.Name(), kind, a.typeString(v))
		return
	}
	m.Value = sharedABIOfInt(v, vi)
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s needs an initializer with MaxEntries (e.g. bpf.%s[V]{MaxEntries: N})", obj.Name(), obj.Type().(*types.Named).Origin().Obj().Name())
		return
	}
	cl, isCL := vs.Values[i].(*ast.CompositeLit)
	if !isCL {
		a.report(Rejected, GB009MapDeclShape, vs.Values[i].Pos(), nil, "map %s: the initializer must be a composite literal with MaxEntries", obj.Name())
		return
	}
	var rest []ast.Expr
	for _, el := range cl.Elts {
		kv, isKV := el.(*ast.KeyValueExpr)
		key, _ := kv.Key.(*ast.Ident)
		if isKV && key != nil && key.Name == "ZeroSeed" && kind == "bloom_filter" {
			tv := a.info.Types[kv.Value]
			if tv.Value == nil || tv.Value.Kind() != constant.Bool {
				a.report(Rejected, GB006NonConstant, kv.Value.Pos(), nil, "map %s: ZeroSeed must be a constant bool", obj.Name())
				return
			}
			if constant.BoolVal(tv.Value) {
				m.Flags = bpfZeroSeed
			}
			continue
		}
		rest = append(rest, el)
	}
	lit := *cl
	lit.Elts = rest
	if !a.mapInit(m, &lit) {
		return
	}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// keylessPlace reports whether a keyless map operation is outside a loop (inside one it reports GB018 and returns false).
func (l *lowerer) keylessPlace(m *BpfMap, call *ast.CallExpr, name string) bool {
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.%s cannot be called inside a loop (bpf-mlir does not allow map.push / pop / peek / bloom.peek in a loop body)", m.Symbol, name)
		return false
	}
	return true
}

// keylessStatus lowers `Q.Push(v, flag)`, `B.Push(v)` and `B.Peek(v)` (an i64 raw status).
func (l *lowerer) keylessStatus(call *ast.CallExpr, m *BpfMap, e apiEntry) (value, bool) {
	name := sel(call)
	if !l.keylessPlace(m, call, name) {
		return value{}, false
	}
	flags := "any"
	if e.op == "keyless_push" {
		tv := l.a.info.Types[call.Args[1]]
		n, exact := uint64(0), false
		if tv.Value != nil {
			n, exact = constUint64(tv)
		}
		switch {
		case tv.Value == nil || !exact:
			l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the flag of %s.Push must be the constant bpf.PushAny or bpf.PushExist", m.Symbol)
			return value{}, false
		case n == 2:
			flags = "exist"
		case n != 0:
			l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the flag of %s.Push must be bpf.PushAny or bpf.PushExist", m.Symbol)
			return value{}, false
		}
	}
	defer l.at(call.Pos())()
	v, ok := l.mapValue(m, call.Args[0])
	if !ok {
		return value{}, false
	}
	r := l.val()
	if e.op == "bloom_peek" {
		l.emit("%s = ebpf.bloom.peek %s, %s : %s, %s -> i64", r, l.mapArgs[m], v, l.mapType(m), m.Value.mlir())
	} else {
		l.emit("%s = ebpf.map.push %s, %s flags %q : %s, %s -> i64", r, l.mapArgs[m], v, flags, l.mapType(m), m.Value.mlir())
	}
	return value{r, vtype{bits: 64, signed: true}}, true
}

// keylessPopAssign lowers `v, st := Q.Pop()` / `Q.Peek()` (either may be `_`). handled reports whether the right-hand side of s is that call.
func (l *lowerer) keylessPopAssign(s *ast.AssignStmt) bool {
	if len(s.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	m, e, name, known := l.mapMethod(call)
	if m == nil || !known || (e.op != "keyless_pop" && e.op != "keyless_peek") {
		return false
	}
	defer l.at(call.Pos())()
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
		return true
	}
	if !l.keylessPlace(m, call, name) {
		return true
	}
	op := map[string]string{"keyless_pop": "ebpf.map.pop", "keyless_peek": "ebpf.map.peek"}[e.op]
	t := vtypeOf(*m.Value.Int)
	r := l.val()
	l.emit("%s:2 = %s %s : %s -> i64, %s", r, op, l.mapArgs[m], l.mapType(m), t.mlir())
	results := []value{{r + "#1", t}, {r + "#0", vtype{bits: 64, signed: true}}}
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
