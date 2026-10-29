package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"strings"
)

// cgroup_sysctl programs (bpf-mlir v1.11.0's kind cgroup_sysctl and ebpf.sysctl.set_new_value):
//
//	ctx.Write() / ctx.FilePos()  → ebpf.ctx.field %ctx "write" / "file_pos" : !ebpf.ctx<"cgroup_sysctl"> -> i32 (the ctx field table in sockcg.go)
//	ctx.SetFilePos(v)            → ebpf.ctx.field.store %ctx "file_pos", %v
//	ctx.SetNewValue("63\n")      → %st = ebpf.sysctl.set_new_value %ctx "63\0A" : !ebpf.ctx<"cgroup_sysctl"> -> i64
//
// The SetNewValue value must be **a string constant only** (bpf-mlir's literal of 1 to 64 bytes, no trailing NUL added). bpf-mlir's op accepts only the
// program's own entry ctx and refuses callee / loop / callback — the frontend stops the same places with a position (GB008 / GB018).

// sysctlMaxLiteral is the literal limit (bytes) of bpf-mlir's ebpf.sysctl.set_new_value.
const sysctlMaxLiteral = 64

// sysctlSet turns `ctx.SetNewValue(s)` into ebpf.sysctl.set_new_value (the value is the raw i64 status). handled reports whether e is that call.
func (l *lowerer) sysctlSet(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "sysctl_set" {
		return value{}, false, false
	}
	sel, _ := ast.Unparen(e.Fun).(*ast.SelectorExpr)
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "cgroup_sysctl" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.SetNewValue may only be called in the body of a cgroup_sysctl program (func f(ctx *bpf.CgroupSysctlContext) bpf.CgroupAction) — a subprogram cannot take the context")
		return value{}, false, true
	}
	if id, ok := ast.Unparen(sel.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.SetNewValue must be called on the program's context parameter")
		return value{}, false, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "ctx.SetNewValue cannot be called inside a loop (bpf-mlir does not allow ebpf.sysctl.set_new_value in a loop body) — call it before the loop")
		return value{}, false, true
	}
	arg := e.Args[0]
	tv := l.a.info.Types[arg]
	if tv.Value == nil || tv.Value.Kind() != constant.String {
		l.fail(Rejected, GB008ProgramShape, arg.Pos(), "ctx.SetNewValue takes a string constant (the new value is a fixed literal — bpf-mlir ebpf.sysctl.set_new_value), not a computed value")
		return value{}, false, true
	}
	s := constant.StringVal(tv.Value)
	if len(s) < 1 || len(s) > sysctlMaxLiteral {
		l.fail(Rejected, GB008ProgramShape, arg.Pos(), "the value of ctx.SetNewValue must be 1 to %d bytes (got %d — bpf-mlir ebpf.sysctl.set_new_value)", sysctlMaxLiteral, len(s))
		return value{}, false, true
	}
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.sysctl.set_new_value %%ctx %s : !ebpf.ctx<\"cgroup_sysctl\"> -> i64", r, mlirBytes(s))
	return value{r, vtype{bits: 64, signed: true}}, true, true
}

// sysctlSetDiscarded turns the statement `ctx.SetNewValue(s)` (status discarded) into the op (false for other statements). bpf-mlir keeps the call even with an unused status.
func (l *lowerer) sysctlSetDiscarded(call *ast.CallExpr) bool {
	_, _, handled := l.sysctlSet(call)
	return handled
}

// mlirBytes turns bytes into an MLIR string literal (printable ASCII as is, `"`, `\` and the rest as `\XX` — the same form as MLIR's printer).
func mlirBytes(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 0x20 && c < 0x7f && c != '"' && c != '\\' {
			b.WriteByte(c)
			continue
		}
		fmt.Fprintf(&b, "\\%02X", c)
	}
	b.WriteByte('"')
	return b.String()
}
