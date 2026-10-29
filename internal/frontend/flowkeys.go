package frontend

import "go/ast"

// flow_dissector programs (bpf-mlir v1.11.0's kind flow_dissector and ebpf.flow_keys.load / .store):
//
//	ctx.Nhoff()        → %v = ebpf.flow_keys.load %ctx "nhoff" : !ebpf.ctx<"flow_dissector"> -> i16
//	ctx.SetSport(v)    → ebpf.flow_keys.store %ctx "sport", %v : !ebpf.ctx<"flow_dissector">, i16
//
// Fields and widths follow the `ctxfield bpf_flow_keys` rows of bpf-mlir's UAPI table (the 4-element ipv6_src / ipv6_dst arrays are not exposed — see limits). bpf-mlir's op
// accepts only the flow_dissector program's entry ctx (static funcs are refused) — the frontend stops subprogram calls with a position (GB008).

// flowKeyFields maps a flow_keys method name (without Set) to (field, width in bits).
var flowKeyFields = map[string]struct {
	field string
	bits  int
}{
	"Nhoff": {"nhoff", 16}, "Thoff": {"thoff", 16}, "AddrProto": {"addr_proto", 16},
	"IsFrag": {"is_frag", 8}, "IsFirstFrag": {"is_first_frag", 8}, "IsEncap": {"is_encap", 8}, "IPProto": {"ip_proto", 8},
	"NProto": {"n_proto", 16}, "Sport": {"sport", 16}, "Dport": {"dport", 16},
	"IPv4Src": {"ipv4_src", 32}, "IPv4Dst": {"ipv4_dst", 32}, "Flags": {"flags", 32}, "FlowLabel": {"flow_label", 32},
}

// flowKeysCall returns (field, width, is-write) if call is a flow_keys method.
func (l *lowerer) flowKeysCall(call *ast.CallExpr) (*ast.SelectorExpr, string, int, bool, bool) {
	op := l.callOp(call)
	if op != "flow_keys_load" && op != "flow_keys_store" {
		return nil, "", 0, false, false
	}
	sel, _ := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	name := sel.Sel.Name
	write := op == "flow_keys_store"
	if write {
		name = name[len("Set"):]
	}
	f := flowKeyFields[name]
	return sel, f.field, f.bits, write, true
}

// flowKeysPlace checks that a flow_keys method is called on the program context in the body of a flow_dissector program.
func (l *lowerer) flowKeysPlace(call *ast.CallExpr, sel *ast.SelectorExpr) bool {
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "flow_dissector" {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.%s reads or writes the flow keys of a flow_dissector program — it may only be called in the body of the program (bpf-mlir accepts ebpf.flow_keys only on the entry context; a subprogram cannot take it)", sel.Sel.Name)
		return false
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.%s must be called on the program's context parameter", sel.Sel.Name)
		return false
	}
	return true
}

// flowKeysRead turns `ctx.<Field>()` into ebpf.flow_keys.load. handled reports whether e is that call.
func (l *lowerer) flowKeysRead(e *ast.CallExpr) (value, bool, bool) {
	sel, field, bits, write, ok := l.flowKeysCall(e)
	if !ok {
		return value{}, false, false
	}
	if write {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s has no value — call it as a statement", sel.Sel.Name)
		return value{}, false, true
	}
	if !l.flowKeysPlace(e, sel) {
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.flow_keys.load %%ctx %q : !ebpf.ctx<\"flow_dissector\"> -> i%d", r, field, bits)
	return value{r, vtype{bits: bits}}, true, true
}

// flowKeysWrite turns the statement `ctx.Set<Field>(v)` into ebpf.flow_keys.store (false for other statements).
func (l *lowerer) flowKeysWrite(call *ast.CallExpr) bool {
	sel, field, bits, write, ok := l.flowKeysCall(call)
	if !ok {
		return false
	}
	if !write {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "the value of ctx.%s is discarded — use it", sel.Sel.Name)
		return true
	}
	if !l.flowKeysPlace(call, sel) {
		return true
	}
	defer l.at(call.Pos())()
	t := vtype{bits: bits}
	v, ok := l.expr(call.Args[0], &t)
	if !ok {
		return true
	}
	l.emit("ebpf.flow_keys.store %%ctx %q, %s : !ebpf.ctx<\"flow_dissector\">, i%d", field, v.name, bits)
	return true
}
