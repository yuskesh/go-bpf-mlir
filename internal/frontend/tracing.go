package frontend

import (
	"go/ast"
	"go/token"
	"go/types"
	"sort"
	"strconv"
	"strings"
)

// Task information for tracing (bpf-mlir's task.pid_tgid, ktime.ns and task.comm):
//
//	bpf.CurrentPidTgid()                → ebpf.task.pid_tgid : i64
//	bpf.KtimeNs()                       → ebpf.ktime.ns : i64
//	Events.Output(Ev{Comm: bpf.CurrentComm()})  → record.make (Comm is 0) → store_record → ebpf.task.comm %res "comm" → submit
//
// The frontend does not restrict helpers by program kind (the same as bpf-mlir's compile — whether the helper is usable in that program type is decided by the check at load time
// on the helper rows of the requirements).

// taskOp returns the op if call is a bpf task information function ("pid_tgid" / "ktime" / "current_comm").
func (l *lowerer) taskOp(call *ast.CallExpr) string {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	obj := l.a.info.Uses[sel.Sel]
	if obj == nil || !inAPIPackage(obj) {
		return ""
	}
	e, known := lookupAPI(obj)
	if !known {
		return ""
	}
	switch e.op {
	case "pid_tgid", "ktime", "current_comm":
		return e.op
	}
	return ""
}

// taskInfo lowers CurrentPidTgid / KtimeNs in an expression. CurrentComm is accepted only as a field value of the record literal of Output.
func (l *lowerer) taskInfo(e ast.Expr) (value, bool, bool) {
	call, isCall := e.(*ast.CallExpr)
	if !isCall {
		return value{}, false, false
	}
	op := l.taskOp(call)
	if op == "" {
		return value{}, false, false
	}
	defer l.at(call.Pos())()
	r := l.val()
	switch op {
	case "pid_tgid":
		l.emit("%s = ebpf.task.pid_tgid : i64", r)
	case "ktime":
		l.emit("%s = ebpf.ktime.ns : i64", r)
	default:
		l.fail(Rejected, GB001UnsupportedConstruct, call.Pos(), "bpf.CurrentComm() may only be the value of a [16]uint8 field in a ring buffer event literal (`Events.Output(Ev{Comm: bpf.CurrentComm()})` — the name is written into the reserved event)")
		return value{}, false, true
	}
	return value{r, vtype{bits: 64}}, true, true
}

// fexitRet lowers `ctx.Ret()` of a fexit program to `ebpf.ctx.retval %ctx after <nargs> : !ebpf.ctx<"fexit"> -> iW`.
// nargs comes from the directive, width and sign from R of FexitContext (the same as the schema's ret — ebpf-verify-schema checks it, and retsig checks it against the kernel before load).
func (l *lowerer) fexitRet(call *ast.CallExpr) (value, bool, bool) {
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Ret" {
		return value{}, false, false
	}
	id, ok := ast.Unparen(sel.X).(*ast.Ident)
	if !ok || l.ctxVar == nil || l.a.info.Uses[id] != l.ctxVar || l.progKind == nil {
		return value{}, false, false
	}
	k := l.progKind.Kind
	if k != "fexit" && !isRetprobeKind(k) { // also kretprobe_multi and uretprobe_multi
		return value{}, false, false
	}
	if l.prog == nil || l.prog.Ret == nil {
		l.failed = true // already reported (GB008 — the return value type)
		return value{}, false, true
	}
	defer l.at(call.Pos())()
	r := l.val()
	t := vtypeOf(*l.prog.Ret)
	if k != "fexit" {
		// the return value of kretprobe / uretprobe (the raw bits of rax — bpf-mlir's probe.retval).
		l.emit("%s = ebpf.probe.retval %%ctx : !ebpf.ctx<%q> -> %s", r, k, t.mlir())
		return value{r, t}, true, true
	}
	l.emit("%s = ebpf.ctx.retval %%ctx after %d : !ebpf.ctx<\"fexit\"> -> %s", r, l.prog.Nargs, t.mlir())
	return value{r, t}, true, true
}

// kprobeArch is the arch of a kprobe program (bpf-mlir's schema supports only x86_64).
const kprobeArch = "x86_64"

// kprobeMaxArg is the number of register-passed arguments on x86_64 (bpf-mlir's UAPI table — rdi, rsi, rdx, rcx, r8, r9).
const kprobeMaxArg = 6

// paramOrder returns the n of the kprobe params in ascending order.
func (p *Program) paramOrder() []int {
	var ns []int
	for n := range p.Params {
		ns = append(ns, n)
	}
	sort.Ints(ns)
	return ns
}

// kprobeArg lowers `bpf.KprobeArg[T](ctx, n)` of a kprobe program to `ebpf.kprobe.arg %ctx n : !ebpf.ctx<"kprobe"> -> iW`.
// n is a constant 1 to 6, T an 8 to 64 bit integer (bpf.KprobeInt). It collects n → T per program (the schema's params); reading the same n as another type is GB008.
// The value is the raw register bits truncated to iW (bpf-mlir's lowering) — reading a 32-bit argument as int32 / uint32 uses only the low 32 bits.
func (l *lowerer) kprobeArg(call *ast.CallExpr) (value, bool, bool) {
	var obj types.Object
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.IndexExpr:
		if sel, ok := f.X.(*ast.SelectorExpr); ok {
			obj = l.a.info.Uses[sel.Sel]
		}
	case *ast.SelectorExpr:
		obj = l.a.info.Uses[f.Sel]
	}
	if obj == nil || !inAPIPackage(obj) {
		return value{}, false, false
	}
	e, known := lookupAPI(obj)
	if !known || (e.op != "kprobe_arg" && e.op != "uprobe_arg") {
		return value{}, false, false
	}
	kind, fn := "kprobe", "bpf.KprobeArg"
	if e.op == "uprobe_arg" {
		kind, fn = "uprobe", "bpf.UprobeArg" // the same rule (a register read)
	}
	defer l.at(call.Pos())()
	if l.calleeAttach(call.Pos(), fn) { // a callee that takes the context
		return value{}, false, true
	}
	if l.progKind == nil || l.prog == nil || (l.progKind.Kind != kind && l.progKind.Kind != kind+"_multi") { // also kprobe_multi and uprobe_multi
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be called in the body of a %s program (func f(ctx *bpf.%sContext) with //gobpf:%s)", fn, kind, strings.ToUpper(kind[:1])+kind[1:], kind)
		return value{}, false, true
	}
	ctxKind := l.progKind.Kind
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return value{}, false, true
	}
	n, ok := l.argNumber(call.Args[1], fn)
	if !ok {
		return value{}, false, true
	}
	if isUintptr(l.a.info.Types[call].Type) {
		// a pointer argument only as the in-place conversion `uint64(bpf.KprobeArg[uintptr](ctx, n))` (a uintptr value is outside the subset).
		l.fail(Rejected, GB001UnsupportedConstruct, call.Pos(), "%s[uintptr] (a pointer argument) must be converted at once: `uint64(%s[uintptr](ctx, %s))` — a uintptr value is not in the subset (the pointer is a raw value, never dereferenced)", fn, fn, types.ExprString(call.Args[1]))
		return value{}, false, true
	}
	it, ok := intTypeOf(l.a.info.Types[call].Type)
	if !ok {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s reads an 8 / 16 / 32 / 64-bit integer", fn)
		return value{}, false, true
	}
	p := l.prog
	if ppos, isPtr := p.PtrParams[n]; isPtr {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the %s program %s is read as a pointer at %s and as %s here — one argument has one type (schema params)", n, kind, p.Symbol, posString(l.a.position(ppos)), goIntName(it))
		return value{}, false, true
	}
	if p.Params == nil {
		p.Params, p.paramPos = map[int]IntType{}, map[int]token.Pos{}
	}
	if spos, isStr := p.StrParams[n]; isStr {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the uprobe program %s is read as a user string at %s and as an integer here — one argument has one type", n, p.Symbol, posString(l.a.position(spos)))
		return value{}, false, true
	}
	if bpos, isBuf := p.BufParams[n]; isBuf {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the uprobe program %s is read as a user buffer at %s and as an integer here — one argument has one type", n, p.Symbol, posString(l.a.position(bpos)))
		return value{}, false, true
	}
	if prev, seen := p.Params[n]; seen && prev != it {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the %s program %s is read as %s here but as %s at %s — one argument has one type (schema params)", n, kind, p.Symbol, goIntName(it), goIntName(prev), posString(l.a.position(p.paramPos[n])))
		return value{}, false, true
	} else if !seen {
		p.Params[n], p.paramPos[n] = it, call.Pos()
	}
	r := l.val()
	t := vtypeOf(it)
	l.emit("%s = ebpf.%s.arg %%ctx %d : !ebpf.ctx<%q> -> %s", r, kind, n, ctxKind, t.mlir())
	return value{r, t}, true, true
}

// goIntName returns the Go spelling of an integer type (for diagnostics).
func goIntName(t IntType) string {
	if t.Signed {
		return "int" + strconv.Itoa(t.Bits)
	}
	return "uint" + strconv.Itoa(t.Bits)
}

// allParamOrder returns the n of integer and user string arguments in ascending order (the schema's params).
func (p *Program) allParamOrder() []int {
	ns := p.paramOrder()
	for n := range p.StrParams {
		ns = append(ns, n)
	}
	for n := range p.StrArrParams {
		ns = append(ns, n)
	}
	for n := range p.PtrParams {
		ns = append(ns, n)
	}
	for n := range p.BufParams {
		ns = append(ns, n)
	}
	sort.Ints(ns)
	return ns
}

// kprobePtrConv lowers `uint64(bpf.KprobeArg[uintptr](ctx, n))` (int64 too) — the raw 8-byte value of a kprobe pointer argument — to
// `ebpf.kprobe.arg %ctx n : !ebpf.ctx<"kprobe"> -> i64` and sets the schema's params to `{"kind":"ptr"}`.
// The value is never dereferenced (no read through it). handled reports whether e has this shape. `uint64(bpf.UprobeArg[uintptr](ctx, n))` of
// a uprobe program is the same (`ebpf.uprobe.arg … -> i64` — the requirements' uprobearg … ptr, format 18).
func (l *lowerer) kprobePtrConv(e *ast.CallExpr) (value, bool, bool) {
	if len(e.Args) != 1 {
		return value{}, false, false
	}
	call, ok := ast.Unparen(e.Args[0]).(*ast.CallExpr)
	if !ok || !isUintptr(l.a.info.Types[call].Type) {
		return value{}, false, false
	}
	if op := l.callOp(call); op == "uprobe_arg" {
		return l.uprobePtrConv(e, call)
	} else if op != "kprobe_arg" {
		return value{}, false, false
	}
	defer l.at(call.Pos())()
	const fn = "bpf.KprobeArg[uintptr]"
	to, isInt := intTypeOf(l.a.info.Types[e].Type)
	if !isInt || to.Bits != 64 {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "%s is the raw 8-byte pointer value — convert it to uint64 or int64 (`uint64(%s(ctx, n))`), got %s", fn, fn, l.a.info.Types[e].Type)
		return value{}, false, true
	}
	if l.calleeAttach(call.Pos(), fn) { // a callee that takes the context
		return value{}, false, true
	}
	if l.progKind == nil || l.progKind.Kind != "kprobe" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be called in the body of a kprobe program (func f(ctx *bpf.KprobeContext) with //gobpf:kprobe)", fn)
		return value{}, false, true
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return value{}, false, true
	}
	n, ok := l.argNumber(call.Args[1], fn)
	if !ok {
		return value{}, false, true
	}
	p := l.prog
	if prev, seen := p.Params[n]; seen {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the kprobe program %s is read as a pointer here but as %s at %s — one argument has one type (schema params)", n, p.Symbol, goIntName(prev), posString(l.a.position(p.paramPos[n])))
		return value{}, false, true
	}
	if p.PtrParams == nil {
		p.PtrParams = map[int]token.Pos{}
	}
	if _, seen := p.PtrParams[n]; !seen {
		p.PtrParams[n] = call.Pos()
	}
	r := l.val()
	l.emit("%s = ebpf.kprobe.arg %%ctx %d : !ebpf.ctx<\"kprobe\"> -> i64", r, n)
	return value{r, vtypeOf(to)}, true, true
}

// isUintptr reports whether t is uintptr (including named uintptr types).
func isUintptr(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.Uintptr
}
