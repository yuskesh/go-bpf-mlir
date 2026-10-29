package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// bpf() from a syscall program (bpf-mlir's ebpf.sys.bpf / ebpf.sys.close):
//
//	st := bpf.SysBpf(ctx, bpf.SysBpfMapCreate, MkAttr{MapType: 2, KeySize: 4, …})
//	→ %r = ebpf.record.make … : !ebpf.record<"MkAttr", 44>
//	  %st = ebpf.sys.bpf %ctx, "map_create", %r : !ebpf.ctx<"syscall">, !ebpf.record<"MkAttr", 44> -> i64
//	c := bpf.SysClose(ctx, int32(st))
//	→ %c = ebpf.sys.close %ctx, %fd : !ebpf.ctx<"syscall"> -> i64
//
// Only top-level statements of the body `x := …` / `x = …` / `_ = …` (the shapes bpf-mlir measured). bpf-mlir's ebpf-compile stops an attr above
// the size limit with SysBpfAttr.def (go does not check it again — one source of truth). The attr layout (field order) is the user's responsibility and is not checked.

// sysBpfCmds maps a SysBpfCmd constant value to bpf-mlir's cmd name (bpfcmd in the UAPI table).
var sysBpfCmds = map[int64]string{0: "map_create", 14: "map_get_fd_by_id", 22: "map_freeze"}

// sysCallAssign lowers `x := bpf.SysBpf(…)` / `bpf.SysClose(…)` (one left-hand side, `=` or `:=`, `_` allowed). handled reports whether the right-hand side is that call.
func (l *lowerer) sysCallAssign(s *ast.AssignStmt) bool {
	if len(s.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
	if !ok {
		return false
	}
	op := l.callOp(call)
	if op != "sys_bpf" && op != "sys_close" {
		return false
	}
	fn := map[string]string{"sys_bpf": "bpf.SysBpf", "sys_close": "bpf.SysClose"}[op]
	if !l.sysCallPlace(call, fn, s) {
		return true
	}
	if len(s.Lhs) != 1 || (s.Tok != token.DEFINE && s.Tok != token.ASSIGN) {
		l.fail(Rejected, GB008ProgramShape, s.Pos(), "%s returns one status — write `st := %s(…)` or `_ = %s(…)`", fn, fn, fn)
		return true
	}
	var v value
	if op == "sys_bpf" {
		v, ok = l.sysBpf(call)
	} else {
		v, ok = l.sysClose(call)
	}
	if !ok {
		return true
	}
	id, _ := s.Lhs[0].(*ast.Ident)
	if id == nil {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Lhs[0].Pos(), "assignment target must be a local variable")
		return true
	}
	if id.Name == "_" {
		return true
	}
	lv := l.localVar(id, s.Tok == token.DEFINE)
	if lv == nil {
		l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "assignment target %s must be a local variable", id.Name)
		return true
	}
	l.setVar(id, lv, v)
	return true
}

// sysCallPlace checks the place (a top-level statement of a syscall program's body, with the program's context as the first argument). A nil s is an expression context (stops).
func (l *lowerer) sysCallPlace(call *ast.CallExpr, fn string, s ast.Stmt) bool {
	if l.progKind == nil || l.progKind.Kind != "syscall" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be used in the body of a syscall program (func f(ctx *bpf.SyscallContext) bpf.SyscallRet)", fn)
		return false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s cannot be called inside a loop — write it as a top-level statement of the program body", fn)
		return false
	}
	top := false
	for _, st := range l.fnBody.List {
		if s != nil && st == s {
			top = true
		}
	}
	if !top {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s must be a top-level statement of the syscall program body, `st := %s(ctx, …)` (bpf-mlir measured it there — not inside if or as part of an expression)", fn, fn)
		return false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return false
	}
	return true
}

// sysBpf lowers a SysBpf call (its place already checked) to record.make and sys.bpf.
func (l *lowerer) sysBpf(call *ast.CallExpr) (value, bool) {
	cmd := ""
	if tv := l.a.info.Types[call.Args[1]]; tv.Value != nil {
		if n, exact := constant.Int64Val(tv.Value); exact {
			cmd = sysBpfCmds[n]
		}
	}
	if cmd == "" {
		l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the cmd of bpf.SysBpf must be the constant bpf.SysBpfMapCreate, bpf.SysBpfMapGetFdByID or bpf.SysBpfMapFreeze")
		return value{}, false
	}
	arg := call.Args[2]
	t := l.a.info.Types[arg].Type
	if _, isNamed := t.(*types.Named); !isNamed {
		l.fail(Rejected, GB008ProgramShape, arg.Pos(), "bpf.SysBpf takes a record value as attr (a composite literal of a named struct type of this package — its layout must match the cmd's struct of union bpf_attr), not %s", t)
		return value{}, false
	}
	if _, isLit := ast.Unparen(arg).(*ast.CompositeLit); !isLit {
		l.fail(Rejected, GB008ProgramShape, arg.Pos(), "bpf.SysBpf takes attr as a composite literal written in place (`MkAttr{…}`)")
		return value{}, false
	}
	rec, ok := l.a.recordOf(t, arg.Pos(), "bpf.SysBpf")
	if !ok {
		l.failed = true
		return value{}, false
	}
	rv, ok := l.recordMake(arg, rec)
	if !ok {
		return value{}, false
	}
	defer l.at(call.Pos())()
	r := l.val()
	l.emit("%s = ebpf.sys.bpf %%ctx, %q, %s : !ebpf.ctx<\"syscall\">, %s -> i64", r, cmd, rv, rec.mlir())
	return value{r, vtype{bits: 64, signed: true}}, true
}

// sysClose lowers a SysClose call to sys.close.
func (l *lowerer) sysClose(call *ast.CallExpr) (value, bool) {
	i32 := vtype{bits: 32, signed: true}
	fd, ok := l.expr(call.Args[1], &i32)
	if !ok {
		return value{}, false
	}
	defer l.at(call.Pos())()
	r := l.val()
	l.emit("%s = ebpf.sys.close %%ctx, %s : !ebpf.ctx<\"syscall\"> -> i64", r, fd.name)
	return value{r, vtype{bits: 64, signed: true}}, true
}

// sysCallDiscarded stops a SysBpf / SysClose expression statement (it discards the status — GB017). handled reports whether call is that call.
func (l *lowerer) sysCallDiscarded(call *ast.CallExpr) bool {
	op := l.callOp(call)
	if op != "sys_bpf" && op != "sys_close" {
		return false
	}
	fn := map[string]string{"sys_bpf": "bpf.SysBpf", "sys_close": "bpf.SysClose"}[op]
	l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the raw status of %s is discarded — use it (`st := %s(…)`) or discard it explicitly (`_ = %s(…)`)", fn, fn, fn)
	return true
}

// sysCallExpr stops SysBpf / SysClose in an expression context (outside the right-hand side of an assignment). handled reports whether e is that call.
func (l *lowerer) sysCallExpr(e *ast.CallExpr) bool {
	op := l.callOp(e)
	if op != "sys_bpf" && op != "sys_close" {
		return false
	}
	fn := map[string]string{"sys_bpf": "bpf.SysBpf", "sys_close": "bpf.SysClose"}[op]
	l.sysCallPlace(e, fn, nil)
	return true
}
