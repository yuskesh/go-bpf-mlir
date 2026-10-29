package frontend

import (
	"go/ast"
	"go/constant"
)

// Reading the ctx of a syscall program (bpf-mlir's ebpf.ctx.load):
//
//	a := bpf.SyscallLoad[uint32](ctx, 4)  → %a = ebpf.ctx.load %ctx[4] : !ebpf.ctx<"syscall"> -> i32
//
// off is a constant, a multiple of T's width, and off + width ≤ 65535 (bpf-mlir's constraint — the kernel's syscall_prog_is_valid_access checks alignment on 6.12 / 6.6,
// and off < U16_MAX on all three versions). Only the context parameter of the program body; stops inside a loop (outside bpf-mlir's evidence — GB018).

// syscallCtxMax is the upper bound of off + width for bpf-mlir's ebpf.ctx.load.
const syscallCtxMax = 65535

// syscallLoad lowers `bpf.SyscallLoad[T](ctx, off)` to ebpf.ctx.load. handled reports whether e is that call.
func (l *lowerer) syscallLoad(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "syscall_load" {
		return value{}, false, false
	}
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "syscall" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "bpf.SyscallLoad may only be called in the body of a syscall program (func f(ctx *bpf.SyscallContext) bpf.SyscallRet) — a subprogram cannot take the context")
		return value{}, false, true
	}
	if id, ok := ast.Unparen(e.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Args[0].Pos(), "the first argument of bpf.SyscallLoad must be the program's context parameter")
		return value{}, false, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "bpf.SyscallLoad cannot be called inside a loop (the ctx read is verified outside loops only) — read it before the loop")
		return value{}, false, true
	}
	var it IntType
	ok := false
	if inst, found := l.a.info.Instances[tpArgIdent(e)]; found && inst.TypeArgs != nil && inst.TypeArgs.Len() >= 1 {
		it, ok = intTypeOf(inst.TypeArgs.At(0))
	}
	if !ok {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "the type argument of bpf.SyscallLoad must be an integer type int8 to uint64")
		return value{}, false, true
	}
	tv := l.a.info.Types[e.Args[1]]
	if tv.Value == nil {
		l.fail(Rejected, GB006NonConstant, e.Args[1].Pos(), "the offset of bpf.SyscallLoad must be a constant (the ctx read is at a fixed offset)")
		return value{}, false, true
	}
	off, exact := constant.Int64Val(constant.ToInt(tv.Value))
	w := int64(it.Bits / 8)
	if !exact || off < 0 || off%w != 0 || off+w > syscallCtxMax {
		l.fail(Rejected, GB008ProgramShape, e.Args[1].Pos(), "the offset of bpf.SyscallLoad[%s] must be a multiple of %d with offset + %d ≤ %d (got %s — bpf-mlir ebpf.ctx.load)", it.mlir(), w, w, syscallCtxMax, tv.Value.ExactString())
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.ctx.load %%ctx[%d] : !ebpf.ctx<\"syscall\"> -> %s", r, off, it.mlir())
	return value{r, vtypeOf(it)}, true, true
}
