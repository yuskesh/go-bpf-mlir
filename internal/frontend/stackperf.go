package frontend

import (
	"go/ast"
	"go/types"
)

// Stack traces and perf events (bpf-mlir's ebpf.stack.kernel_id and ebpf.perf.output).
//
//	var Stacks = bpf.StackTrace{MaxEntries: 256, Depth: 32}   → stack_trace: u32 → u64 × Depth, flags 0
//	var Events = bpf.PerfEventArray[Ev]{}                     → perf_event_array: u32 → u32, max_entries 0 (the loader sets the number of possible CPUs), record Ev
//	st := Stacks.KernelID(ctx, 0)          → %st = ebpf.stack.kernel_id %ctx, %m skip 0 : !ebpf.ctx<"fentry">, … -> i64
//	st := Stacks.KernelIDReuse(ctx, 3)     → … skip 3 reuse …
//	ps := Events.Output(ctx, Ev{…})        → %r = ebpf.record.make …; %ps = ebpf.perf.output %ctx, %m, %r : … -> i64
//
// All of them only in the body of a fentry program (bpf-mlir's op verifier), the status is raw (i64), a statement that discards it is GB017 (an explicit `_ =` is accepted),
// and they cannot be placed in a loop body.

// stackSkipMax is the upper bound of skip (the UAPI's BPF_F_SKIP_FIELD_MASK 0xff — the same value as the stackflag row of bpf-mlir's UAPI table; ebpf-compile refuses anything above).
const stackSkipMax = 255

// perfInstance returns V if t is an instance of bpf.PerfEventArray[V].
func perfInstance(t types.Type) (types.Type, bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg || n.Origin().Obj().Name() != "PerfEventArray" {
		return nil, false
	}
	args := n.TypeArgs()
	if args == nil || args.Len() != 1 {
		return nil, false
	}
	return args.At(0), true
}

// collectStackTrace checks and collects stack trace map declarations (MaxEntries and Depth are positive constants).
// buildID is bpf.StackBuildID (the element is struct bpf_stack_build_id, flags BPF_F_STACK_BUILD_ID).
func (a *analyzer) collectStackTrace(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, buildID bool) {
	u32, u64 := types.Typ[types.Uint32], types.Typ[types.Uint64]
	m := &BpfMap{Symbol: obj.Name(), Kind: "stack_trace", Pos: a.position(name.Pos()), obj: obj, Key: sharedABIOfInt(u32, IntType{32, false})}
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "stack trace map %s needs an initializer bpf.StackTrace{MaxEntries: N, Depth: D} (both are required)", obj.Name())
		return
	}
	cl, ok := vs.Values[i].(*ast.CompositeLit)
	if !ok {
		a.report(Rejected, GB009MapDeclShape, vs.Values[i].Pos(), nil, "stack trace map %s: the initializer must be a composite literal bpf.StackTrace{MaxEntries: N, Depth: D}", obj.Name())
		return
	}
	got := map[string]uint64{}
	for _, el := range cl.Elts {
		kv, isKV := el.(*ast.KeyValueExpr)
		var key *ast.Ident
		if isKV {
			key, _ = kv.Key.(*ast.Ident)
		}
		if key == nil || (key.Name != "MaxEntries" && key.Name != "Depth") {
			a.report(Rejected, GB009MapDeclShape, el.Pos(), nil, "stack trace map %s: only the fields MaxEntries and Depth may be set", obj.Name())
			return
		}
		tv := a.info.Types[kv.Value]
		if tv.Value == nil {
			a.report(Rejected, GB006NonConstant, kv.Value.Pos(), nil, "stack trace map %s: %s must be a constant", obj.Name(), key.Name)
			return
		}
		n, exact := constUint64(tv)
		if !exact || n == 0 {
			a.report(Rejected, GB009MapDeclShape, kv.Value.Pos(), nil, "stack trace map %s: %s must be a positive constant", obj.Name(), key.Name)
			return
		}
		got[key.Name] = n
		if key.Name == "MaxEntries" {
			m.maxPos = kv.Value.Pos()
		}
	}
	for _, f := range []string{"MaxEntries", "Depth"} {
		if _, ok := got[f]; !ok {
			a.report(Rejected, GB009MapDeclShape, cl.Pos(), nil, "stack trace map %s: %s is required", obj.Name(), f)
			return
		}
	}
	d := got["Depth"]
	m.MaxEntries = got["MaxEntries"]
	elem := sharedABIOfInt(u64, IntType{64, false})
	if buildID {
		elem = SharedABI{Kind: ABIStackBuildID, Size: stackBuildIDSize, Align: 8}
		m.Flags = stackFlagBuildID
	}
	m.Value = SharedABI{Kind: ABIArray, GoType: types.NewArray(u64, int64(d)), Size: elem.Size * d, Align: 8, Array: &ArrayABI{Count: d, Elem: elem}}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// collectPerf checks and collects perf event map declarations (V is a record, the initializer is an empty literal or absent — MaxEntries is 0 by convention).
func (a *analyzer) collectPerf(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, v types.Type) {
	u32 := types.Typ[types.Uint32]
	m := &BpfMap{Symbol: obj.Name(), Kind: "perf_event_array", Pos: a.position(name.Pos()), obj: obj,
		Key: sharedABIOfInt(u32, IntType{32, false}), Value: sharedABIOfInt(u32, IntType{32, false})}
	if _, isStruct := v.Underlying().(*types.Struct); !isStruct {
		a.report(Rejected, GB016SharedABIShape, name.Pos(), nil, "perf event array %s: the event type must be a record (a named struct type declared in this package), got %s", obj.Name(), a.typeString(v))
		return
	}
	rv, ok := a.recordOf(v, name.Pos(), "perf event array "+obj.Name()+" event")
	if !ok {
		return
	}
	m.Event = &rv
	if len(vs.Values) == len(vs.Names) {
		cl, isCL := vs.Values[i].(*ast.CompositeLit)
		if !isCL || len(cl.Elts) > 0 {
			a.report(Rejected, GB009MapDeclShape, vs.Values[i].Pos(), nil, "perf event array %s: the initializer must be the empty literal bpf.PerfEventArray[V]{} (the loader sizes it to the possible CPUs)", obj.Name())
			return
		}
	}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// stackPerfCall lowers `M.KernelID(ctx, skip)` / `M.KernelIDReuse(ctx, skip)` / `M.Output(ctx, v)` (perf). handled reports whether call is one of them.
func (l *lowerer) stackPerfCall(call *ast.CallExpr) (value, bool, bool) {
	m, e, name, known := l.mapMethod(call)
	user := e.op == "stack_user_id" || e.op == "stack_user_id_reuse" // the user stack
	if m == nil || !known || (e.op != "stack_id" && e.op != "stack_id_reuse" && e.op != "perf_output" && !user) {
		return value{}, false, false
	}
	defer l.at(call.Pos())()
	helper := "bpf_get_stackid"
	if e.op == "perf_output" {
		helper = "bpf_perf_event_output"
	}
	if user {
		if l.progKind == nil || (l.prog == nil && !l.calleeCtx) || (l.progKind.Kind != "fentry" && l.progKind.Kind != "kprobe" && l.progKind.Kind != "uprobe") { // also in a callee that takes the context
			kind := "subprogram"
			if l.progKind != nil {
				kind = l.progKind.Kind
			}
			l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.%s (%s with BPF_F_USER_STACK) may only be called in the body of a uprobe, kprobe or fentry program — not in a %s", m.Symbol, name, helper, kind)
			return value{}, false, true
		}
	} else if l.progKind == nil || l.progKind.Kind != "fentry" || (l.prog == nil && !l.calleeCtx) { // also in a callee that takes the context
		kind := "subprogram"
		if l.progKind != nil {
			kind = l.progKind.Kind
		}
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.%s (%s) may only be called in the body of a fentry program (func f(ctx *bpf.FentryContext) with //gobpf:fentry) — not in a %s", m.Symbol, name, helper, kind)
		return value{}, false, true
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s.%s must be the program's context parameter", m.Symbol, name)
		return value{}, false, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.%s cannot be inside a loop (bpf-mlir does not allow %s in a loop body)", m.Symbol, name, helper)
		return value{}, false, true
	}
	r := l.val()
	if e.op == "perf_output" {
		made, ok := l.recordMake(call.Args[1], *m.Event)
		if !ok {
			return value{}, false, true
		}
		l.emit("%s = ebpf.perf.output %%ctx, %s, %s : !ebpf.ctx<\"fentry\">, %s, %s -> i64", r, l.mapArgs[m], made, l.mapType(m), m.Event.mlir())
		return value{r, vtype{bits: 64, signed: true}}, true, true
	}
	tv := l.a.info.Types[call.Args[1]]
	if tv.Value == nil {
		l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the skip of %s.%s must be a constant (0 to %d)", m.Symbol, name, stackSkipMax)
		return value{}, false, true
	}
	skip, exact := constUint64(tv)
	if !exact || skip > stackSkipMax {
		l.fail(Rejected, GB009MapDeclShape, call.Args[1].Pos(), "the skip %s of %s.%s is outside 0 to %d (the UAPI skip field of bpf_get_stackid is 8 bits)", tv.Value.ExactString(), m.Symbol, name, stackSkipMax)
		return value{}, false, true
	}
	reuse := ""
	if e.op == "stack_id_reuse" || e.op == "stack_user_id_reuse" {
		reuse = " reuse"
	}
	if user {
		l.emit("%s = ebpf.stack.user_id %%ctx, %s skip %d%s : !ebpf.ctx<%q>, %s -> i64", r, l.mapArgs[m], skip, reuse, l.progKind.Kind, l.mapType(m))
		return value{r, vtype{bits: 64, signed: true}}, true, true
	}
	l.emit("%s = ebpf.stack.kernel_id %%ctx, %s skip %d%s : !ebpf.ctx<\"fentry\">, %s -> i64", r, l.mapArgs[m], skip, reuse, l.mapType(m))
	return value{r, vtype{bits: 64, signed: true}}, true, true
}

// PerfMaps returns the names of the perf_event_array maps the program outputs to (Program.PerfMaps in the generated file — gobpf.AttachFentry checks that a reader exists).
func (p *Program) PerfMaps() []string {
	var out []string
	for _, m := range p.Maps {
		if m.Kind == "perf_event_array" {
			out = append(out, m.Symbol)
		}
	}
	return out
}

// Build id stacks: the element is struct bpf_stack_build_id (32 bytes), the map flags are BPF_F_STACK_BUILD_ID.
const (
	stackBuildIDSize = 32
	stackFlagBuildID = 32
)
