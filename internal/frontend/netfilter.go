package frontend

import "go/ast"

// netfilter programs (bpf-mlir's netfilter kind — the same shape as bpf-mlir's kernel/netfilter/mlir/nf.mlir):
//
//	ctx.Hook()    → %s = ebpf.ctx.field %ctx "state" : !ebpf.ctx<"netfilter"> -> !ebpf.kptr<"nf_hook_state">
//	                %h = ebpf.kfield.load %s "hook" : !ebpf.kptr<"nf_hook_state"> -> i8
//	ctx.PF()      → … "pf" -> i8
//	ctx.SkbLen()  → %k = ebpf.ctx.field %ctx "skb" : … -> !ebpf.kptr<"sk_buff">; ebpf.kfield.load %k "len" -> i32
//
// nf_hook_state (hook and pf, u8) and sk_buff (len, u32) are local types in the schema's kernel_types (CO-RE — the same fields as the schema of bpf-mlir's nf.mlir).

// nfReads maps a method to (ctx field, kernel type, kernel field, width).
var nfReads = map[string]struct {
	ctxField, kt, field string
	bits                int
}{
	"Hook":   {"state", "nf_hook_state", "hook", 8},
	"PF":     {"state", "nf_hook_state", "pf", 8},
	"SkbLen": {"skb", "sk_buff", "len", 32},
}

// nfKernelTypes adds the nf_hook_state and sk_buff local types to the schema's kernel_types on first use.
func (a *analyzer) nfKernelTypes() {
	have := map[string]bool{}
	for _, kt := range a.kernelOrder {
		have[kt.Name] = true
	}
	if !have["nf_hook_state"] {
		a.kernelOrder = append(a.kernelOrder, &KernelType{Name: "nf_hook_state", Note: "builtin local type of the netfilter program's state (CO-RE)", Fields: []KernelField{
			{Name: "hook", GoName: "hook", Kind: kfInt, Bits: 8},
			{Name: "pf", GoName: "pf", Kind: kfInt, Bits: 8},
		}})
	}
	if !have["sk_buff"] {
		a.kernelOrder = append(a.kernelOrder, &KernelType{Name: "sk_buff", Note: "builtin local type of the netfilter program's skb (CO-RE)", Fields: []KernelField{{Name: "len", GoName: "len", Kind: kfInt, Bits: 32}}})
	}
}

// nfRead lowers `ctx.Hook()` / `ctx.PF()` / `ctx.SkbLen()` to ctx.field and kfield.load. handled reports whether e is that call.
func (l *lowerer) nfRead(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "nf_read" {
		return value{}, false, false
	}
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	name := sel.Sel.Name
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "netfilter" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s may only be called in the body of a netfilter program (func f(ctx *bpf.NetfilterContext) bpf.NFAction)", name)
		return value{}, false, true
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.%s must be called on the program's context parameter", name)
		return value{}, false, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "ctx.%s cannot be called inside a loop (bpf-mlir does not allow kfield of kernel pointers in a loop body) — call it before the loop", name)
		return value{}, false, true
	}
	l.a.nfKernelTypes()
	r := nfReads[name]
	defer l.at(e.Pos())()
	p := l.val()
	l.emit("%s = ebpf.ctx.field %%ctx %q : !ebpf.ctx<\"netfilter\"> -> !ebpf.kptr<%q>", p, r.ctxField, r.kt)
	v := l.val()
	l.emit("%s = ebpf.kfield.load %s %q : !ebpf.kptr<%q> -> i%d", v, p, r.field, r.kt, r.bits)
	return value{v, vtype{bits: r.bits}}, true, true
}
