package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"sort"
	"strings"
)

// lowering — turns eBPF-side function bodies into ① ops. Only the shapes in this file's switch are accepted;
// anything else stops with a position and a reason code.
//
// Variables live in an environment of SSA values (env). Outer variables assigned in arms (ebpf.if, ref.check present / absent) merge as region results.
// **i1 is never a region result** (bool is widened to i8 for yield and restored with cmpi ne 0 after the arm). **One exit** (return only as the last statement).

// vtype is the type of an SSA value: bool (i1) or an integer with width and signedness.
type vtype struct {
	bits   int
	signed bool
	isBool bool
}

func (t vtype) mlir() string {
	if t.isBool {
		return "i1"
	}
	return fmt.Sprintf("i%d", t.bits)
}

func vtypeOf(t IntType) vtype { return vtype{bits: t.Bits, signed: t.Signed} }

// carrier returns the type carried in region results and subprogram arguments and results (bool is i8).
func (t vtype) carrier() vtype {
	if t.isBool {
		return vtype{bits: 8}
	}
	return t
}

type value struct {
	name string
	t    vtype
}

// goType turns a Go type into a vtype (integers and bool only).
func goType(t types.Type) (vtype, bool) {
	if t == nil {
		return vtype{}, false
	}
	b, ok := t.Underlying().(*types.Basic)
	if !ok {
		return vtype{}, false
	}
	switch b.Kind() {
	case types.Bool, types.UntypedBool:
		return vtype{isBool: true}, true
	case types.Uint8:
		return vtype{bits: 8}, true
	case types.Uint16:
		return vtype{bits: 16}, true
	case types.Uint32:
		return vtype{bits: 32}, true
	case types.Uint64, types.Uint: // uintptr is not accepted (a pointer-sized type)
		return vtype{bits: 64}, true
	case types.Int8:
		return vtype{bits: 8, signed: true}, true
	case types.Int16:
		return vtype{bits: 16, signed: true}, true
	case types.Int32:
		return vtype{bits: 32, signed: true}, true
	case types.Int64, types.Int:
		return vtype{bits: 64, signed: true}, true
	}
	return vtype{}, false
}

// fnLowering is the lowering state of one function (a program or a subprogram).
type lowerer struct {
	callback       *TimerCallback         // lowering a timer callback body
	urbCB          *UrbCallback           // lowering a user_ringbuf drain callback body
	urbFields      map[string]value       // reads of the drain callback sample's fields (name → dynptr.read value)
	kptrs          map[*types.Var]kptrVal // tp_btf kernel pointer variables
	maybeRefs      map[*types.Var]refArg  // a subprogram's unchecked borrowed arguments (ref.check via `if p != nil`)
	a              *analyzer
	name           string // the program / subprogram name (the head of paths)
	isProg         bool
	b              *strings.Builder
	next           int
	indent         string
	mapArgs        map[*BpfMap]string
	env            map[*types.Var]value
	checked        *checkedRef   // the innermost checked borrow (nil if none)
	borrows        []*checkedRef // the stack of checked borrows (outer to inner — up to depth 2)
	pos            token.Pos     // the current Go position (the emit loc)
	failed         bool
	ctxVar         *types.Var            // the program context parameter (nil in subprograms)
	windows        map[*types.Var]window // live packet windows (inside in_range)
	winWritable    bool                  // the subprogram's window argument is writable (all callers are xdp)
	escaped        bool                  // the current region ends in break / continue (the arm has no yield)
	loops          []*loopCtx            // enclosing loops (inner to outer)
	guard          *indexGuard           // the then arm of a shape A range check
	rguards        []*rangeGuard         // then arms of shape A′ range checks (pushed inner to outer)
	thenGuard      *rangeGuard           // a shape A′ check to push onto the next ifStmt's then arm (set by rangeGuardIf)
	progKind       *ctxKind              // the program context's kind (the verdict table); for a subprogram taking the context, that kind
	calleeCtx      bool                  // whether this is the body of a subprogram taking the context (stops attach-dependent reads, invalidating ops and terminators)
	commOK         bool                  // inside an Output event literal (accepts bpf.CurrentComm)
	commPaths      []string              // CurrentComm fields in that literal (Output emits task.comm)
	prog           *Program              // the program being lowered (nil in subprograms — fexit's nargs and return type)
	bounds         map[string]uint64     // inclusive upper bounds per SSA value name (proofs of variable Array keys)
	inFallback     bool                  // inside a tail call fallback region (stops a second TailCall)
	checkArmDepth  int                   // depth of ctx.Check arms inside a loop (stops break / continue not at the end of an arm)
	fnBody         *ast.BlockStmt        // the body of the function being lowered (where AtomicAdd deltas come from)
	pktGen         int                   // the packet generation (+1 per Adjust — checks for stale windows)
	lastAdjust     token.Pos             // the position of the last Adjust (for error messages)
	lastAdjustName string
	resv           *reservation        // the present arm of the current ring buffer reservation (`if e, ok := M.Reserve(); ok { … }`)
	resvVars       map[*types.Var]bool // reservation variables e (stops use outside present)
}

type checkedRef struct {
	obj    *types.Var
	borrow string
	elem   vtype          // an integer map value
	rec    *SharedABI     // a record map value (nil for integers — lower_record.go)
	m      *BpfMap        // the Lookup map (for timer Init)
	key    constant.Value // the Lookup key's value if constant (alias check for two borrows of the same map — GB029)
}

// borrowOf returns the borrow if v is one of the current checked borrows (outer or inner), else nil. Ops on a borrow look it up
// from the expression's root variable (l.checked is the innermost borrow — for "inside a checked branch?" and the focus of regions closed over one borrow).
func (l *lowerer) borrowOf(v *types.Var) *checkedRef {
	if v == nil {
		return nil
	}
	for i := len(l.borrows) - 1; i >= 0; i-- {
		if l.borrows[i].obj == v {
			return l.borrows[i]
		}
	}
	return nil
}

// pushBorrow pushes a checked borrow onto the stack (l.checked is the innermost borrow). popBorrow pops it.
func (l *lowerer) pushBorrow(c *checkedRef) {
	l.borrows = append(l.borrows, c)
	l.checked = c
}

func (l *lowerer) popBorrow() {
	l.borrows = l.borrows[:len(l.borrows)-1]
	l.checked = nil
	if n := len(l.borrows); n > 0 {
		l.checked = l.borrows[n-1]
	}
}

// calleeAttach stops attach-dependent reads inside a subprogram that takes the context (bpf-mlir v1.2.0 refuses ctx.arg, ctx.retval,
// kprobe.arg and uprobe.arg in callees). It returns true if it stopped one (already reported).
func (l *lowerer) calleeAttach(p token.Pos, what string) bool {
	if !l.calleeCtx {
		return false
	}
	l.fail(Rejected, GB013SubprogramShape, p, "%s reads an attach-specific value, which a subprogram that takes the context cannot do (bpf-mlir refuses it in a callee); read it in the program and pass it as an integer argument", what)
	return true
}

// focus sets l.checked to the borrow only during ops closed over one borrow (the WithLock region, timer ops); the returned function restores it.
func (l *lowerer) focus(c *checkedRef) func() {
	prev := l.checked
	l.checked = c
	return func() { l.checked = prev }
}

// refArg is a subprogram's unchecked borrowed argument: the SSA name and the pointee type.
type refArg struct {
	ref string
	abi SharedABI
}

func (l *lowerer) path(extra ...string) []string { return append([]string{l.name}, extra...) }

func (l *lowerer) fail(v Verdict, c Code, p token.Pos, format string, args ...any) {
	l.a.report(v, c, p, l.path(), format, args...)
	l.failed = true
}

func (l *lowerer) val() string {
	s := fmt.Sprintf("%%v%d", l.next)
	l.next++
	return s
}

func (l *lowerer) emit(format string, args ...any) {
	l.b.WriteString(l.indent)
	fmt.Fprintf(l.b, format, args...)
	l.b.WriteString(l.locSuffix(l.pos)) // the Go position
	l.b.WriteByte('\n')
}

// at sets the current Go position to p and returns a function that restores it (`defer l.at(n.Pos())()`).
func (l *lowerer) at(p token.Pos) func() {
	old := l.pos
	if p.IsValid() {
		l.pos = p
	}
	return func() { l.pos = old }
}

// locSuffix returns the op suffix ` loc("<file>":L:C)` (file is relative to the package directory — an absolute path would break byte-identical generated files).
func (l *lowerer) locSuffix(p token.Pos) string {
	if !p.IsValid() {
		return ""
	}
	if !l.a.locInRange(p) {
		l.failed = true // already reported (GB022) — stop generating this function
		return ""
	}
	return locText(l.a.position(p))
}

// The widths of BTF line_info's line_col (22-bit line, 10-bit column — bpf-mlir v0.6.0 makes an out-of-range loc a compile error under auto).
const (
	maxLocLine   = 1 << 20
	maxLocColumn = 1023
)

// locInRange reports whether p's line and column are within the line_info range. If not, it reports GB022 once (a review point — never silently set the column to 0).
func (a *analyzer) locInRange(p token.Pos) bool {
	q := a.position(p)
	if a.lineInfoOff || (q.Line <= maxLocLine && q.Column <= maxLocColumn) {
		return true
	}
	key := fmt.Sprintf("%s:%d:%d", q.Filename, q.Line, q.Column)
	if !a.locReported[key] {
		a.locReported[key] = true
		a.report(Rejected, GB022LocRange, p, nil, "this Go code is at line %d, column %d — beyond what BTF line_info can record (line <= %d, column <= %d); shorten the line, or generate with `go tool gobpf -line-info=off` (no line_info in the ELF)", q.Line, q.Column, maxLocLine, maxLocColumn)
	}
	return false
}

func locText(q token.Position) string {
	return fmt.Sprintf(" loc(%q:%d:%d)", q.Filename, q.Line, q.Column)
}

// region lowers body one level deeper into a separate builder and returns its text.
func (l *lowerer) region(body func()) string {
	outerB, outerIndent := l.b, l.indent
	var sb strings.Builder
	l.b, l.indent = &sb, outerIndent+"  "
	body()
	l.b, l.indent = outerB, outerIndent
	return sb.String()
}

func copyEnv(e map[*types.Var]value) map[*types.Var]value {
	out := make(map[*types.Var]value, len(e))
	for k, v := range e {
		out[k] = v
	}
	return out
}

func (l *lowerer) bindMaps(ms []*BpfMap) {
	for i, m := range ms {
		l.mapArgs[m] = fmt.Sprintf("%%m%d", i)
	}
}

func (a *analyzer) lowerProgram(p *Program) {
	l := &lowerer{a: a, name: p.Symbol, isProg: true, b: &strings.Builder{}, indent: "  ", mapArgs: map[*BpfMap]string{}, env: map[*types.Var]value{}, bounds: map[string]uint64{}}
	l.fnBody = p.decl.Body
	a.bindInnerHandles(p.decl.Body)      // map-in-map inner handles (before the RMW check and lowering)
	l.checkRMW(p.decl, nil, nil)         // non-atomic RMW on shared maps (rmw.go)
	p.Maps = argMaps(a.closures[p].Maps) // the closure's maps (computed in one place, closure.go). Ring buffers are looked up by name, so excluded
	l.bindMaps(p.Maps)
	l.ctxVar = p.obj.Type().(*types.Signature).Params().At(0)
	l.progKind = p.kind
	l.prog = p
	if !a.locInRange(p.decl.Name.Pos()) { // the program's closing loc is the declaration position (emit.go — out of range is GB022)
		l.failed = true
	}
	stmts := p.decl.Body.List
	if p.kind.Action == "" {
		// A program without a result (fentry): the body (minus a final bare `return`) followed by the verdict done (returns 0).
		if n := len(stmts); n > 0 {
			if r, isRet := stmts[n-1].(*ast.ReturnStmt); isRet && len(r.Results) == 0 {
				stmts = stmts[:n-1]
			}
		}
		l.stmts(stmts)
		func() {
			defer l.at(p.decl.Body.Rbrace)()
			l.emit("ebpf.verdict %q", "done")
		}()
		if !l.failed {
			p.body = l.b.String()
		}
		return
	}
	if len(stmts) == 0 {
		l.fail(Rejected, GB001UnsupportedConstruct, p.decl.Body.Rbrace, "program %s must end with `return <%s>`", p.Symbol, p.kind.returnForm())
		return
	}
	// A conditional verdict: the body's final `if c { return A } else { return B }`.
	if is, ok := stmts[len(stmts)-1].(*ast.IfStmt); ok && l.isVerdictIf(is, true) && !l.hasTailCall(stmts[:len(stmts)-1]) {
		l.stmts(stmts[:len(stmts)-1])
		l.verdictIf(is, is.Body.List[0].(*ast.ReturnStmt), is.Else.(*ast.BlockStmt).List[0].(*ast.ReturnStmt))
		if !l.failed {
			p.body = l.b.String()
		}
		return
	}
	last, isRet := stmts[len(stmts)-1].(*ast.ReturnStmt)
	if !isRet {
		l.fail(Rejected, GB001UnsupportedConstruct, stmts[len(stmts)-1].Pos(), "program %s must end with `return <%s>`", p.Symbol, p.kind.returnForm())
		return
	}
	body := stmts[:len(stmts)-1]
	// A conditional verdict: the body's final `if c { return A }` + `return B` → ebpf.verdict.if c "A" else "B".
	if n := len(body); n > 0 {
		if is, ok := body[n-1].(*ast.IfStmt); ok && l.isVerdictIf(is, false) && !l.hasTailCall(body[:n-1]) && !l.isRedirectReturn(last) {
			l.stmts(body[:n-1])
			l.verdictIf(is, is.Body.List[0].(*ast.ReturnStmt), last)
			if !l.failed {
				p.body = l.b.String()
			}
			return
		}
	}
	// Tail calls: a top-level TailCall / TailCallIf in the body is a terminator — the following statements and the final return form the fallback region.
	for k, s := range body {
		if call, op := l.tailCallOp(s); call != nil {
			l.stmts(body[:k])
			if !l.failed {
				l.tailCall(call, op, body[k+1:], last)
			}
			if !l.failed {
				p.body = l.b.String()
			}
			return
		}
	}
	l.stmts(body)
	l.ret(last)
	if !l.failed {
		p.body = l.b.String()
	}
}

func (a *analyzer) lowerSubprogram(s *Subprogram) {
	l := &lowerer{a: a, name: s.Symbol, b: &strings.Builder{}, indent: "  ", mapArgs: map[*BpfMap]string{}, env: map[*types.Var]value{}, bounds: map[string]uint64{}}
	l.fnBody = s.decl.Body
	l.checkRMW(s.decl, nil, nil)                     // non-atomic RMW on shared maps (rmw.go)
	s.Maps = argMaps(a.summaries[keyOf(s.obj)].Maps) // maps the body refers to directly (the summary — excluding ring buffers)
	if !a.locInRange(s.decl.Name.Pos()) {
		l.failed = true
	}
	l.bindMaps(s.Maps)
	restore := l.at(s.decl.Pos()) // bool argument conversions use the declaration position
	sig := s.obj.Type().(*types.Signature)
	for i := 0; i < sig.Params().Len(); i++ {
		pv := sig.Params().At(i)
		t := s.params[i]
		arg := fmt.Sprintf("%%a%d", i)
		if s.ctx != nil && i == 0 { // the program context parameter (block argument %ctx — Check, stack ids and perf Output lower the same as in the body)
			l.ctxVar, l.progKind, l.calleeCtx = pv, s.ctx, true
			continue
		}
		if s.win != nil && s.win.idx == i { // the packet window parameter (the length the caller checked — valid in the whole body)
			if l.windows == nil {
				l.windows = map[*types.Var]window{}
			}
			l.windows[pv] = window{name: arg, n: s.win.n, gen: l.pktGen}
			l.winWritable = s.win.writes != token.NoPos // all callers are xdp (checked by resolveWinParams)
			continue
		}
		if pp := s.ptrs[i]; pp != nil { // a borrowed map value argument
			if pp.kind == "maybe_ref" {
				if l.maybeRefs == nil {
					l.maybeRefs = map[*types.Var]refArg{}
				}
				l.maybeRefs[pv] = refArg{arg, pp.abi}
				continue
			}
			vi, _ := pp.abi.intType()
			var rec *SharedABI
			if pp.abi.Kind == ABIRecord {
				v := pp.abi
				rec = &v
			}
			l.pushBorrow(&checkedRef{obj: pv, borrow: arg, elem: vtypeOf(vi), rec: rec}) // checked in the whole body (the caller checked the value)
			continue
		}
		if t.isBool {
			// A bool arrives as i8 and is restored to i1 inside.
			z := l.val()
			l.emit("%s = arith.constant 0 : i8", z)
			b := l.val()
			l.emit("%s = arith.cmpi ne, %s, %s : i8", b, arg, z)
			l.env[pv] = value{b, t}
		} else {
			l.env[pv] = value{arg, t}
		}
	}
	stmts := s.decl.Body.List
	if len(stmts) == 0 {
		l.fail(Rejected, GB013SubprogramShape, s.decl.Body.Rbrace, "subprogram %s must end with `return <value>`", s.Symbol)
		return
	}
	last, isRet := stmts[len(stmts)-1].(*ast.ReturnStmt)
	if !isRet || len(last.Results) != 1 {
		l.fail(Rejected, GB013SubprogramShape, stmts[len(stmts)-1].Pos(), "subprogram %s must end with a single `return <value>` (one exit)", s.Symbol)
		return
	}
	restore()
	l.stmts(stmts[:len(stmts)-1])
	defer l.at(last.Pos())()
	v, ok := l.expr(last.Results[0], &s.result)
	if !ok {
		return
	}
	v = l.toCarrier(v)
	l.emit("ebpf.return %s : %s", v.name, v.t.mlir())
	if !l.failed {
		s.body = l.b.String()
	}
}

// toCarrier widens bool to i8 (region results, subprogram boundaries).
func (l *lowerer) toCarrier(v value) value {
	if !v.t.isBool {
		return v
	}
	r := l.val()
	l.emit("%s = arith.extui %s : i1 to i8", r, v.name)
	return value{r, vtype{bits: 8}}
}

// fromCarrier restores a bool carried as i8 to i1.
func (l *lowerer) fromCarrier(name string, t vtype) value {
	if !t.isBool {
		return value{name, t}
	}
	z := l.val()
	l.emit("%s = arith.constant 0 : i8", z)
	r := l.val()
	l.emit("%s = arith.cmpi ne, %s, %s : i8", r, name, z)
	return value{r, t}
}

// --- statements ---

func (l *lowerer) stmts(list []ast.Stmt) {
	for i, s := range list {
		if l.failed {
			return
		}
		if br, ok := s.(*ast.BranchStmt); ok && i != len(list)-1 {
			l.fail(Rejected, GB018LoopShape, br.Pos(), "%s must be the last statement of its block (the statements after it never run)", br.Tok)
			return
		}
		l.stmt(s)
	}
}

func (l *lowerer) stmt(s ast.Stmt) {
	defer l.at(s.Pos())()
	switch s := s.(type) {
	case *ast.ExprStmt:
		call, ok := s.X.(*ast.CallExpr)
		if !ok {
			l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "expression statement is not a supported call")
			return
		}
		if l.windowStore(call) { // w.SetBE16(i, v) etc.
			return
		}
		if l.ctxFieldWrite(call) { // ctx.SetUserPort(v) etc.
			return
		}
		if l.sessionWrite(call) { // ctx.SetCookie(v) (fsession)
			return
		}
		if l.sysctlSetDiscarded(call) { // a statement discarding the status of ctx.SetNewValue(s)
			return
		}
		if l.tpBufStore(call) { // ctx.SetBuffer(v) (raw_tp_writable's writable buffer)
			return
		}
		if l.flowKeysWrite(call) { // ctx.Set<Field>(v) (flow_dissector's flow_keys)
			return
		}
		if l.kprobeReadDiscarded(call) {
			return
		}
		if l.sysCallDiscarded(call) {
			return
		}
		if l.withLock(call) { // bpf.WithLock(&p.Lock, func() { … })
			return
		}
		if isTimerOp(l.callOp(call)) { // a statement discarding the status of p.T.Init() etc. — GB017 after the shape check
			if _, ok, _ := l.timerCall(call); ok {
				l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the raw status of Timer.%s is discarded — use it (`if st := p.T.Init(); st == 0 { … }`) or discard it explicitly (`_ = p.T.%s(…)`)", sel(call), sel(call))
			}
			return
		}
		if _, _, handled := l.globalCall(call, false); handled { // G.Add(d)
			return
		}
		if op := l.adjustOp(call); op != "" {
			l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the status of ctx.%s (0 or a negative errno) is discarded — check it (`if st := ctx.%s(d); st == 0 { … }`) or discard it explicitly with `_ =`", sel(call), sel(call))
			return
		}
		if tc, _ := l.tailCallOp(s); tc != nil {
			l.rejectTailCall(tc) // lowerProgram takes a top-level TailCall first
			return
		}
		if l.reserveConsume(call) { // M.Submit(e) / M.Discard(e)
			return
		}
		if l.resvScan(call) { // passing or reading the reserved event in other calls (named before the other rules)
			return
		}
		if m, _, _, _ := l.mapMethod(call); m != nil {
			l.mapCall(call)
			return
		}
		if callee := l.subprogramCallee(call); callee != nil {
			l.callSubprogram(call, callee) // the result is discarded
			return
		}
		if l.isFieldAtomicAdd(call) {
			l.fieldAtomicAdd(call)
			return
		}
		if _, isRedirect := l.redirectOp(call); isRedirect {
			l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.Redirect / RedirectIf is a terminator — write it as the program's last statement `return ctx.Redirect(ifindex)` (its value is the requested action, not a delivery result)")
			return
		}
		l.unsupportedCall(call)
	case *ast.IfStmt:
		if l.isKptrCheckIf(s) { // if m := p.F / bpf.FentryArg / bpf.TPArg …; m != nil (kptr.check)
			l.kptrCheckIf(s)
			return
		}
		if iv, arr, ok := l.isIndexGuard(s); ok {
			if arr.end.Array.Elem.Kind == ABIInt && len(arr.vars) == 0 {
				l.indexGuardIf(s, iv, arr)
			} else {
				l.rangeGuardIf(s, iv, arr) // arrays of records, two-dimensional arrays (shape A′)
			}
			return
		}
		if l.isOuterLookupIf(s) { // if m := Outer.Lookup(k); m != nil — map-in-map
			l.ifOuterLookup(s)
			return
		}
		if l.isReserveIf(s) { // if e, ok := M.Reserve(); ok { … }
			l.ifReserve(s)
			return
		}
		if l.isLookupIf(s) {
			l.ifLookup(s)
			return
		}
		if ra, pobj, ok := l.maybeRefIf(s); ok { // `if p != nil { … }` on a subprogram's unchecked borrowed argument
			l.paramRefIf(s, ra, pobj)
			return
		}
		if l.isCheckIf(s) {
			// Accepted in loop bodies too (bpf-mlir v0.9.0 accepts packet.check in a (U) loop body; a (B) body is GB018 in loopmode.go).
			l.checkIf(s)
			return
		}
		l.ifStmt(s)
		l.clampAfterIf(s) // the bound of k after `if k >= C { k = D }`
	case *ast.AssignStmt:
		if l.tpArgAssign(s) { // p := bpf.TPArg[T](ctx, i)
			return
		}
		if l.kprobeReadAssign(s) { // v, st := bpf.KprobeRead[T](ctx, n, off)
			return
		}
		if l.keylessPopAssign(s) { // v, st := Q.Pop() / Q.Peek()
			return
		}
		if l.skAssignAssign(s) { // st, found := M.Assign(ctx, k, flags)
			return
		}
		if l.sysCallAssign(s) { // st := bpf.SysBpf(ctx, cmd, attr) / bpf.SysClose(ctx, fd)
			return
		}
		if l.ksyscallArgAssign(s) { // x := bpf.KsyscallArg[T](ctx, n)
			return
		}
		if l.usdtArgAssign(s) { // v, st := bpf.USDTArg[T](ctx, n)
			return
		}
		if l.reserveAssign(s) { // writes into the reservation: e.F = v, *e = V{…}
			return
		}
		if len(s.Rhs) == 1 {
			if call, outer, isOuter := l.outerLookupCall(s.Rhs[0]); isOuter { // an unchecked outer Lookup
				l.fail(Rejected, GB005NilCheckShape, call.Pos(), "%s.Lookup returns an inner map that may be absent — use it only as `if m := %s.Lookup(k); m != nil { … }`", outer.Symbol, outer.Symbol)
				return
			}
		}
		if l.kfieldCopy(s) { // q.F = p.Comm — a copy of a kernel [N]byte
			return
		}
		if l.kptrStore(s) { // sk.F = v — a write to a struct_ops kernel integer field
			return
		}
		if l.fieldAssign(s) {
			return
		}
		l.assign(s)
	case *ast.DeclStmt:
		l.declStmt(s)
	case *ast.IncDecStmt:
		if l.fieldIncDec(s) {
			return
		}
		l.incDec(s)
	case *ast.BlockStmt:
		l.stmts(s.List)
	case *ast.ForStmt, *ast.RangeStmt:
		l.loopStmt(s)
	case *ast.BranchStmt:
		l.branch(s)
	case *ast.ReturnStmt:
		l.fail(Rejected, GB001UnsupportedConstruct, s.Pos(), "return is only supported as the last statement (one exit), or as the only statement of an arm of the body's final `if c { return A }; return B` / `if c { return A } else { return B }`")
	default:
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "%s is not in the supported subset", stmtKind(s))
	}
}

func stmtKind(s ast.Stmt) string {
	name := fmt.Sprintf("%T", s)
	name = strings.TrimPrefix(name, "*ast.")
	return strings.TrimSuffix(name, "Stmt") + " statement"
}

// localVar returns the variable if id is a local variable (declared inside the function).
func (l *lowerer) localVar(id *ast.Ident, def bool) *types.Var {
	var obj types.Object
	if def {
		obj = l.a.info.Defs[id]
		if obj == nil {
			obj = l.a.info.Uses[id]
		}
	} else {
		obj = l.a.info.Uses[id]
	}
	v, ok := obj.(*types.Var)
	if !ok || v.IsField() || l.a.mapByObj[v] != nil || v.Parent() == l.a.pkg.Types.Scope() {
		return nil
	}
	return v
}

func (l *lowerer) setVar(id *ast.Ident, v *types.Var, val value) {
	if l.borrowOf(v) != nil {
		l.fail(Rejected, GB005NilCheckShape, id.Pos(), "the checked pointer %s must not be reassigned", id.Name)
		return
	}
	want, ok := goType(v.Type())
	if !ok {
		l.badVarType(id.Pos(), id.Name, v.Type())
		return
	}
	if want != val.t {
		l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "internal: value of type %s assigned to %s of type %s", val.t.mlir(), id.Name, want.mlir())
		return
	}
	l.env[v] = val
}

func (l *lowerer) assign(s *ast.AssignStmt) {
	if len(s.Lhs) == 2 && len(s.Rhs) == 1 {
		if call, isLPM := l.isLPMLookup(s.Rhs[0]); isLPM {
			l.lpmLookupAssign(s, call) // v, ok := M.Lookup(a)
			return
		}
		if call, m, isOS, o := l.isOutputStr(s.Rhs[0]); isOS {
			l.outputStrAssign(s, call, m, o) // st, ok := R.OutputStr(v, bpf.UprobeStr(ctx, n)), R.OutputStrOrDiscard, R.OutputKernelStr(v, p.F)
			return
		}
	}
	switch s.Tok {
	case token.DEFINE, token.ASSIGN:
		if len(s.Lhs) != len(s.Rhs) {
			l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "multi-value assignment is not supported")
			return
		}
		// Evaluate all right-hand sides before assigning (Go semantics: a, b = b, a).
		vals := make([]value, len(s.Rhs))
		for i, r := range s.Rhs {
			id, _ := s.Lhs[i].(*ast.Ident)
			if id == nil {
				l.fail(Unknown, GB001UnsupportedConstruct, s.Lhs[i].Pos(), "assignment target must be a local variable")
				return
			}
			if id.Name == "_" {
				// `_ = R.Output(…)` does not use the result (an if_reserved without a result — the same .mlir as the statement).
				if call, isCall := r.(*ast.CallExpr); isCall {
					if m, en, _, known := l.mapMethod(call); m != nil && known && en.side != sideUser && en.op == "output" {
						if _, ok := l.output(call, m, false); !ok {
							return
						}
						continue
					}
				}
				v, ok := l.expr(r, nil)
				if !ok {
					return
				}
				vals[i] = v
				continue
			}
			v := l.localVar(id, s.Tok == token.DEFINE)
			if v != nil && l.borrowOf(v) != nil {
				l.fail(Rejected, GB005NilCheckShape, id.Pos(), "the checked pointer %s must not be reassigned", id.Name)
				return
			}
			if v == nil {
				if uv, _ := l.a.info.Uses[id].(*types.Var); l.borrowOf(uv) != nil {
					l.fail(Rejected, GB005NilCheckShape, id.Pos(), "the checked pointer %s must not be reassigned", id.Name)
					return
				}
				l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "assignment target %s must be a local variable", id.Name)
				return
			}
			want, ok := goType(v.Type())
			if !ok {
				l.badVarType(id.Pos(), id.Name, v.Type())
				return
			}
			val, ok := l.expr(r, &want)
			if !ok {
				return
			}
			l.noteBound(r, val)
			vals[i] = val
		}
		for i, lhs := range s.Lhs {
			id := lhs.(*ast.Ident)
			if id.Name == "_" {
				continue
			}
			l.setVar(id, l.localVar(id, s.Tok == token.DEFINE), vals[i])
		}
	default:
		// op= is the same as x = x op y.
		op, ok := assignOps[s.Tok]
		if !ok || len(s.Lhs) != 1 || len(s.Rhs) != 1 {
			l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
			return
		}
		id, _ := s.Lhs[0].(*ast.Ident)
		var v *types.Var
		if id != nil {
			v = l.localVar(id, false)
		}
		if v == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, s.Lhs[0].Pos(), "assignment target must be a local variable")
			return
		}
		cur, ok := l.env[v]
		if !ok {
			l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "internal: %s has no value", id.Name)
			return
		}
		res, ok := l.binary(s.Pos(), op, cur, s.Rhs[0], cur.t)
		if !ok {
			return
		}
		if ctv := l.a.info.Types[s.Rhs[0]]; ctv.Value != nil && isUnsignedInt(v.Type()) {
			if c, exact := constant.Uint64Val(constant.ToInt(ctv.Value)); exact {
				switch s.Tok {
				case token.AND_ASSIGN:
					l.bounds[res.name] = c
				case token.REM_ASSIGN:
					if c > 0 {
						l.bounds[res.name] = c - 1
					}
				}
			}
		}
		l.setVar(id, v, res)
	}
}

var assignOps = map[token.Token]token.Token{
	token.ADD_ASSIGN: token.ADD, token.SUB_ASSIGN: token.SUB, token.MUL_ASSIGN: token.MUL,
	token.QUO_ASSIGN: token.QUO, token.REM_ASSIGN: token.REM,
	token.AND_ASSIGN: token.AND, token.OR_ASSIGN: token.OR, token.XOR_ASSIGN: token.XOR,
	token.SHL_ASSIGN: token.SHL, token.SHR_ASSIGN: token.SHR, token.AND_NOT_ASSIGN: token.AND_NOT,
}

func (l *lowerer) declStmt(s *ast.DeclStmt) {
	gd, ok := s.Decl.(*ast.GenDecl)
	if !ok || gd.Tok != token.VAR {
		if ok && gd.Tok == token.CONST {
			return // go/types holds local constant values (arith.constant at each use)
		}
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "declaration is not supported (only var and const)")
		return
	}
	for _, sp := range gd.Specs {
		vs := sp.(*ast.ValueSpec)
		for i, name := range vs.Names {
			v := l.localVar(name, true)
			if v == nil {
				l.fail(Unknown, GB001UnsupportedConstruct, name.Pos(), "unsupported variable %s", name.Name)
				return
			}
			t, ok := goType(v.Type())
			if !ok {
				l.badVarType(name.Pos(), name.Name, v.Type())
				return
			}
			var val value
			if i < len(vs.Values) {
				if val, ok = l.expr(vs.Values[i], &t); !ok {
					return
				}
				l.noteBound(vs.Values[i], val)
			} else {
				// The Go zero value. bool uses MakeBool — an integer 0 used as a bool constant used to panic (found by a test).
				if t.isBool {
					val = l.constant(constant.MakeBool(false), t)
				} else {
					val = l.constant(constant.MakeInt64(0), t)
				}
			}
			if name.Name != "_" {
				l.setVar(name, v, val)
			}
		}
	}
}

func (l *lowerer) incDec(s *ast.IncDecStmt) {
	id, _ := s.X.(*ast.Ident)
	var v *types.Var
	if id != nil {
		v = l.localVar(id, false)
	}
	if v == nil {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "++ / -- target must be a local variable")
		return
	}
	cur := l.env[v]
	one := l.constant(constant.MakeInt64(1), cur.t)
	op := "arith.addi"
	if s.Tok == token.DEC {
		op = "arith.subi"
	}
	r := l.val()
	l.emit("%s = %s %s, %s : %s", r, op, cur.name, one.name, cur.t.mlir())
	l.setVar(id, v, value{r, cur.t})
}

// --- if and merges ---

// mergeVars compares the env after an arm with the original and returns the outer variables changed in the arm, in declaration order.
func mergeVars(before map[*types.Var]value, arms ...map[*types.Var]value) []*types.Var {
	var mods []*types.Var
	for v, bv := range before {
		for _, arm := range arms {
			if av, ok := arm[v]; ok && av.name != bv.name {
				mods = append(mods, v)
				break
			}
		}
	}
	sort.Slice(mods, func(i, j int) bool { return mods[i].Pos() < mods[j].Pos() })
	return mods
}

// yieldLine returns the text that yields the values of mods at the end of an arm (bool widened to i8). op is "ebpf.if.yield" or "ebpf.yield".
func (l *lowerer) yieldInto(armText *string, armEnv map[*types.Var]value, mods []*types.Var, op string, pos token.Pos) {
	defer l.at(pos)() // the yield is at the arm's closing position
	outerB, outerIndent := l.b, l.indent
	var sb strings.Builder
	sb.WriteString(*armText)
	l.b, l.indent = &sb, outerIndent+"  "
	var names, typs []string
	for _, v := range mods {
		c := l.toCarrier(armEnv[v])
		names = append(names, c.name)
		typs = append(typs, c.t.mlir())
	}
	if len(mods) == 0 {
		l.emit("%s", op)
	} else {
		l.emit("%s %s : %s", op, strings.Join(names, ", "), strings.Join(typs, ", "))
	}
	l.b, l.indent = outerB, outerIndent
	*armText = sb.String()
}

// results returns the region result name prefix and the type list ("%v3:2 = " etc.).
func (l *lowerer) resultHead(mods []*types.Var, before map[*types.Var]value) (head, typeList, base string) {
	if len(mods) == 0 {
		return "", "", ""
	}
	var typs []string
	for _, v := range mods {
		typs = append(typs, before[v].t.carrier().mlir())
	}
	base = l.val()
	head = base + " = "
	if len(mods) > 1 {
		head = fmt.Sprintf("%s:%d = ", base, len(mods))
	}
	return head, " -> " + strings.Join(typs, ", "), base
}

// bindResults puts the region results into env (bools carried as i8 are restored to i1).
func (l *lowerer) bindResults(mods []*types.Var, before map[*types.Var]value, base string) {
	for i, v := range mods {
		name := base
		if len(mods) > 1 {
			name = fmt.Sprintf("%s#%d", base, i)
		}
		l.env[v] = l.fromCarrier(name, before[v].t)
	}
}

func (l *lowerer) ifStmt(s *ast.IfStmt) {
	tg := l.thenGuard // shape A′: the index is proven only in the then arm — not passed to ifs in the init, condition or else arm
	l.thenGuard = nil
	if s.Init != nil {
		// Evaluate the init statement outside the if (go/types already resolved Go scopes — the variable is visible only inside the if, but its SSA value may live outside).
		l.stmt(s.Init)
		if l.failed {
			return
		}
	}
	bt := vtype{isBool: true}
	c, ok := l.expr(s.Cond, &bt)
	if !ok {
		return
	}
	before := copyEnv(l.env)
	l.env = copyEnv(before)
	l.escaped = false
	gen0 := l.pktGen // each arm starts from the entry's packet generation
	thenText := l.region(func() {
		if tg != nil {
			l.rguards = append(l.rguards, tg)
			defer func() { l.rguards = l.rguards[:len(l.rguards)-1] }()
		}
		l.stmts(s.Body.List)
	})
	thenEnv, thenEsc := l.env, l.escaped
	l.env = copyEnv(before)
	l.escaped = false
	genThen := l.pktGen
	l.pktGen = gen0
	elseText := ""
	if s.Else != nil {
		elseText = l.region(func() {
			switch e := s.Else.(type) {
			case *ast.BlockStmt:
				l.stmts(e.List)
			case *ast.IfStmt:
				l.stmt(e) // else if is an if inside the else arm
			}
		})
	}
	elseEnv, elseEsc := l.env, l.escaped
	l.armGen(gen0, genThen, l.pktGen)
	l.escaped = false
	if l.failed {
		return
	}
	// An arm ending in break / continue does not join the merge and has no yield (the ebpf.break / continue at its end is the terminator).
	mods := mergeVars(before, liveEnvs([]map[*types.Var]value{thenEnv, elseEnv}, []bool{thenEsc, elseEsc})...)
	elsePos := s.End()
	if s.Else != nil {
		elsePos = s.Else.End() - 1
	}
	if !thenEsc {
		l.yieldInto(&thenText, thenEnv, mods, "ebpf.if.yield", s.Body.Rbrace)
	}
	if !elseEsc {
		l.yieldInto(&elseText, elseEnv, mods, "ebpf.if.yield", elsePos)
	}
	l.env = before
	head, typeList, base := l.resultHead(mods, before)
	l.b.WriteString(fmt.Sprintf("%s%sebpf.if %s%s {\n%s%s} else {\n%s%s}%s\n", l.indent, head, c.name, typeList, thenText, l.indent, elseText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(mods, before, base)
	}
}

// --- map ---

func (l *lowerer) mapMethod(call *ast.CallExpr) (*BpfMap, apiEntry, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, apiEntry{}, "", false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return nil, apiEntry{}, "", false
	}
	v, _ := l.a.info.Uses[recv].(*types.Var)
	m := l.a.mapByObj[v]
	if m == nil {
		m = l.a.innerByVar[v] // a map-in-map inner handle
	}
	obj := l.a.info.Uses[sel.Sel]
	if m == nil || obj == nil {
		return nil, apiEntry{}, "", false
	}
	e, known := lookupAPI(obj)
	if !known {
		return m, apiEntry{}, sel.Sel.Name, false
	}
	return m, e, sel.Sel.Name, true
}

func (l *lowerer) mapType(m *BpfMap) string { return mapTypeOf(m) }

// mapTypeOf returns the ebpf type of a map (a stack_trace value is !ebpf.stack<D>).
func mapTypeOf(m *BpfMap) string {
	if m.Kind == "stack_trace" && m.Value.Array.Elem.Kind == ABIStackBuildID {
		return fmt.Sprintf("!ebpf.map<%q, %s, !ebpf.stack_build_id<%d>>", m.Kind, m.Key.mlir(), m.Value.Array.Count)
	}
	if m.Kind == "stack_trace" {
		return fmt.Sprintf("!ebpf.map<%q, %s, !ebpf.stack<%d>>", m.Kind, m.Key.mlir(), m.Value.Array.Count)
	}
	if isKeylessKind(m.Kind) {
		return fmt.Sprintf("!ebpf.map<%q, none, %s>", m.Kind, m.Value.mlir()) // a keyless map
	}
	if m.InnerTpl != nil {
		return fmt.Sprintf("!ebpf.map<%q, %s, %s>", m.Kind, m.Key.mlir(), mapTypeOf(m.InnerTpl)) // the outer value is the inner map type
	}
	return fmt.Sprintf("!ebpf.map<%q, %s, %s>", m.Kind, m.Key.mlir(), m.Value.mlir())
}

// mapCall lowers a map method call as a statement (AtomicAdd / Update).
func (l *lowerer) mapCall(call *ast.CallExpr) {
	m, e, name, ok := l.mapMethod(call)
	if !ok || e.side == sideUser {
		l.failed = true // checkEBPFSide already reported GB002 / GB003
		return
	}
	if e.op == "lookup" {
		l.fail(Rejected, GB005NilCheckShape, call.Pos(), "%s.Lookup must be used as `if p := %s.Lookup(k); p != nil { … }`", m.Symbol, m.Symbol)
		return
	}
	if e.op == "output_str" || e.op == "output_str_discard" || e.op == "output_kernel_str" {
		helper := "probe_read_user_str"
		if e.op == "output_kernel_str" {
			helper = "probe_read_kernel_str"
		}
		l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the status of %s.%s (the raw %s status) and whether it was submitted are discarded — use them (`st, ok := %s.%s(…)`) or discard explicitly (`_, _ = %s.%s(…)`)", m.Symbol, name, helper, m.Symbol, name, m.Symbol, name)
		return
	}
	if e.op == "redirect_map" || e.op == "redirect_map_if" {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.%s is a terminator — write it as the program's last statement `return %s.%s(ctx, …)` (its value is the requested action, not a delivery result)", m.Symbol, name, m.Symbol, name)
		return
	}
	if e.op == "stack_id" || e.op == "stack_id_reuse" || e.op == "stack_user_id" || e.op == "stack_user_id_reuse" || e.op == "perf_output" {
		// GB017 after the shape checks (context, skip, record, loop) so other errors are not hidden — the same order as Output.
		if _, ok, _ := l.stackPerfCall(call); !ok {
			return
		}
		l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the raw status of %s.%s is discarded — use it (`st := %s.%s(…)`) or discard it explicitly (`_ = %s.%s(…)` — choosing not to count failures)", m.Symbol, name, m.Symbol, name, m.Symbol, name)
		return
	}
	if e.op == "storage_get" {
		l.fail(Rejected, GB005NilCheckShape, call.Pos(), "%s.Get may only be used as `if v := %s.Get(owner, bpf.Create); v != nil { … }`", m.Symbol, m.Symbol)
		return
	}
	if e.op == "sk_assign" {
		l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the raw status of %s.Assign (sk_assign) and whether the slot held a socket are discarded — use them (`st, found := %s.Assign(…)`) or discard explicitly (`_, _ = %s.Assign(…)`)", m.Symbol, m.Symbol, m.Symbol)
		return
	}
	if e.op == "keyless_pop" || e.op == "keyless_peek" {
		l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the value and the raw status of %s.%s are discarded — use them (`v, st := %s.%s()`) or discard explicitly (`_, _ = %s.%s()`)", m.Symbol, name, m.Symbol, name, m.Symbol, name)
		return
	}
	if e.op == "lpm_lookup" {
		l.fail(Rejected, GB005NilCheckShape, call.Pos(), "the result of %s.Lookup is discarded — use it as `if v, ok := %s.Lookup(a); ok { … }` or `v, ok := %s.Lookup(a)`", m.Symbol, m.Symbol, m.Symbol)
		return
	}
	if e.op == "output" {
		if _, ok := l.output(call, m, false); !ok {
			return
		}
		// A statement that discards success (bool) and has no drop counter (CountDropsIn) has no way to count dropped events — GB017 (the same policy as hash statuses —
		// a review point). Checked after the shape checks (event, CountDropsIn, loop) so other errors are not hidden.
		if len(call.Args) == 1 {
			l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the result of %s.Output (whether the event was submitted) is discarded and no drop counter is given — a dropped event would go uncounted; use it (`if !%s.Output(…) { … }`), pass bpf.CountDropsIn(<map>, <key>), or discard it explicitly (`_ = %s.Output(…)`)", m.Symbol, m.Symbol, m.Symbol)
		}
		return
	}
	if _, isStatus := statusOps[e.op]; isStatus {
		l.fail(Rejected, GB017StatusIgnored, call.Pos(), "the status of %s.%s is discarded — check it (`if st := %s.%s(…); st != 0 { … }`) or discard it explicitly (`_ = %s.%s(…)`)", m.Symbol, name, m.Symbol, name, m.Symbol, name)
		return
	}
	if m.Value.Kind == ABIRecord {
		l.recordMapCall(call, m, e, name)
		return
	}
	_, okK := m.Key.intType()
	_, okV := m.Value.intType()
	if !okK || !okV {
		l.fail(Unknown, GB016SharedABIShape, call.Pos(), "map %s: only integer keys and values are supported by this operation", m.Symbol)
		return
	}
	k, ok := l.mapKey(m, call.Args[0])
	if !ok {
		return
	}
	v, ok := l.mapValue(m, call.Args[1])
	if !ok {
		return
	}
	switch e.op {
	case "atomic_add":
		l.emit("ebpf.map.atomic_add %s[%s], %s : %s, %s, %s", l.mapArgs[m], k, v, l.mapType(m), m.Key.mlir(), m.Value.mlir())
	case "update":
		l.emit("ebpf.map.update %s[%s], %s : %s, %s, %s", l.mapArgs[m], k, v, l.mapType(m), m.Key.mlir(), m.Value.mlir())
	default:
		l.fail(Unknown, GB002UnsupportedCall, call.Pos(), "%s.%s has no lowering", m.Symbol, name)
	}
}

func (l *lowerer) unsupportedCall(call *ast.CallExpr) {
	var obj types.Object
	switch f := call.Fun.(type) {
	case *ast.Ident:
		obj = l.a.info.Uses[f]
	case *ast.SelectorExpr:
		obj = l.a.info.Uses[f.Sel]
	}
	if inAPIPackage(obj) {
		l.failed = true // checkEBPFSide already reported GB002 / GB003
		return
	}
	name := "this call"
	if obj != nil {
		name = qualifiedName(obj)
	}
	l.fail(Unknown, GB002UnsupportedCall, call.Pos(), "%s is not in gobpf's API table", name)
}

// isLookupIf reports whether s has the shape `if p := M.Lookup(k); …` (the init defines a Lookup call).
func (l *lowerer) isLookupIf(s *ast.IfStmt) bool {
	as, ok := s.Init.(*ast.AssignStmt)
	if !ok || len(as.Rhs) != 1 {
		return false
	}
	call, ok := as.Rhs[0].(*ast.CallExpr)
	if !ok {
		return false
	}
	_, e, _, known := l.mapMethod(call)
	return known && (e.op == "lookup" || e.op == "storage_get") // storage_get for local storage
}

// ifLookup turns `if p := m.Lookup(k); p != nil { … } [else { … }]` into ref.check present / absent (with arm merges).
func (l *lowerer) ifLookup(s *ast.IfStmt) {
	shape := func(p token.Pos, what string) {
		l.fail(Rejected, GB005NilCheckShape, p, "%s — the supported form is `if p := m.Lookup(k); p != nil { … } [else { … }]`", what)
	}
	if len(l.borrows) >= 2 {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "at most two borrows at once — this Lookup is inside the checked branches of %s and %s; copy a value to a local first", l.borrows[0].obj.Name(), l.borrows[1].obj.Name())
		return
	}
	as := s.Init.(*ast.AssignStmt)
	pid, _ := as.Lhs[0].(*ast.Ident)
	if as.Tok != token.DEFINE || len(as.Lhs) != 1 || pid == nil {
		shape(as.Pos(), "the if statement's init must be `p := m.Lookup(k)`")
		return
	}
	call := as.Rhs[0].(*ast.CallExpr)
	m, _, _, _ := l.mapMethod(call)
	pobj, _ := l.a.info.Defs[pid].(*types.Var)
	if !l.isNilCheck(s.Cond, pobj) {
		shape(s.Cond.Pos(), fmt.Sprintf("the condition must be exactly `%s != nil`", pid.Name))
		return
	}
	var elseBlock *ast.BlockStmt
	if s.Else != nil {
		eb, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			shape(s.Else.Pos(), "else-if is not supported")
			return
		}
		elseBlock = eb
		l.rejectUses(eb, pobj, "the checked pointer is nil in the else branch")
		if l.failed {
			return
		}
	}
	if _, okV := m.Value.intType(); !okV && m.Value.Kind != ABIRecord {
		l.fail(Unknown, GB016SharedABIShape, call.Pos(), "map %s: Lookup supports integer or record values", m.Symbol)
		return
	}
	key := l.a.info.Types[call.Args[0]].Value
	_, en, _, _ := l.mapMethod(call)
	if en.op == "storage_get" {
		key = nil // owner is not a constant (a second Get on the same map cannot be shown distinct — GB029)
	}
	if o := l.checked; o != nil && checkBorrowAlias && !l.distinctBorrow(o, m, key, call) {
		return
	}
	emit := l.emitLookup
	if en.op == "storage_get" {
		emit = l.emitStorageGet
	}
	ref, ok := emit(m, call)
	if !ok {
		return
	}
	l.refCheckIf(s, ref, pobj, m.Value, m, key, elseBlock)
}

// checkBorrowAlias turns the GB029 check on or off — **only tests set it to false** (passing .mlir without the check to ebpf-compile confirms that bpf-mlir accepts
// two borrows of the same map — only the frontend is the strict side).
var checkBorrowAlias = true

// distinctBorrow reports whether a second Lookup (map m, key) inside the outer borrow o can be shown to point to a value distinct from o (GB029 if not):
// different maps are distinct. The same map is distinct only when both keys are constants with different values. If the outer borrow is a subprogram's borrowed argument (map unknown),
// it is distinct only when the value types differ (it may point into a map of the same type).
func (l *lowerer) distinctBorrow(o *checkedRef, m *BpfMap, key constant.Value, call *ast.CallExpr) bool {
	alias := func(why string) bool {
		l.fail(Rejected, GB029BorrowAlias, call.Pos(), "%s.Lookup(%s) inside the checked branch of %s may point to the same value as %s (%s) — two borrows of one value are not allowed; copy the value you need to a local before the second Lookup", m.Symbol, types.ExprString(call.Args[0]), o.obj.Name(), o.obj.Name(), why)
		return false
	}
	if o.m == nil {
		sameType := false
		if o.rec != nil {
			sameType = m.Value.Kind == ABIRecord && types.Identical(o.rec.GoType, m.Value.GoType)
		} else if it, ok := m.Value.intType(); ok {
			sameType = vtypeOf(it) == o.elem
		}
		if sameType {
			return alias(fmt.Sprintf("%s is a pointer parameter of the same value type — it may point into %s", o.obj.Name(), m.Symbol))
		}
		return true
	}
	if o.m != m {
		return true
	}
	if o.key == nil || key == nil {
		return alias(fmt.Sprintf("both are values of map %s and the keys are not both constants", m.Symbol))
	}
	if constant.Compare(o.key, token.EQL, key) {
		return alias(fmt.Sprintf("both are values of map %s at the same key %s", m.Symbol, key.ExactString()))
	}
	return true
}

// maybeRefIf reports whether s is `if p != nil { … } [else { … }]` (no init) on a subprogram's unchecked borrowed argument.
func (l *lowerer) maybeRefIf(s *ast.IfStmt) (refArg, *types.Var, bool) {
	if s.Init != nil || len(l.maybeRefs) == 0 {
		return refArg{}, nil, false
	}
	for pv, ra := range l.maybeRefs {
		if l.isNilCheck(s.Cond, pv) {
			return ra, pv, true
		}
	}
	return refArg{}, nil, false
}

// paramRefIf turns `if p != nil` on an unchecked borrowed argument into ref.check (the arm shapes are the same as a Lookup if).
func (l *lowerer) paramRefIf(s *ast.IfStmt, ra refArg, pobj *types.Var) {
	if l.checked != nil {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "a nil check of a pointer parameter inside another checked branch is not supported yet")
		return
	}
	var elseBlock *ast.BlockStmt
	if s.Else != nil {
		eb, ok := s.Else.(*ast.BlockStmt)
		if !ok {
			l.fail(Rejected, GB005NilCheckShape, s.Else.Pos(), "else-if is not supported — the supported form is `if %s != nil { … } [else { … }]`", pobj.Name())
			return
		}
		elseBlock = eb
	}
	l.refCheckIf(s, ra.ref, pobj, ra.abi, nil, nil, elseBlock)
}

// emitLookup emits the ebpf.map.lookup of `M.Lookup(k)` and returns the name of the maybe_ref value (also used for a subprogram's unchecked argument).
func (l *lowerer) emitLookup(m *BpfMap, call *ast.CallExpr) (string, bool) {
	k, ok := l.mapKey(m, call.Args[0])
	if !ok {
		return "", false
	}
	mt := l.mapType(m)
	ref := l.val()
	l.emit("%s = ebpf.map.lookup %s[%s] : %s, %s -> !ebpf.maybe_ref<%s>", ref, l.mapArgs[m], k, mt, m.Key.mlir(), m.Value.mlir())
	return ref, true
}

// refCheckIf lowers the if arms into the present / absent of ref.check on the maybe_ref value ref (for a Lookup if and for `if p != nil` on a subprogram's
// unchecked borrowed argument — m is the Lookup map, nil for an argument; key is the Lookup's constant key). With an outer borrow, in the present arm
// both the outer and inner are checked; in the absent arm only the outer.
func (l *lowerer) refCheckIf(s *ast.IfStmt, ref string, pobj *types.Var, val SharedABI, m *BpfMap, key constant.Value, elseBlock *ast.BlockStmt) {
	vi, _ := val.intType()
	var rec *SharedABI
	if val.Kind == ABIRecord {
		v := val
		rec = &v
	}
	borrow := l.val()
	before := copyEnv(l.env)
	l.env = copyEnv(before)
	l.pushBorrow(&checkedRef{obj: pobj, borrow: borrow, elem: vtypeOf(vi), rec: rec, m: m, key: key})
	l.escaped = false
	presentText := l.region(func() { l.stmts(s.Body.List) })
	l.popBorrow()
	presentEnv, presentEsc := l.env, l.escaped
	l.env = copyEnv(before)
	l.escaped = false
	absentText := ""
	if elseBlock != nil {
		absentText = l.region(func() { l.stmts(elseBlock.List) })
	}
	absentEnv, absentEsc := l.env, l.escaped
	l.escaped = false
	if l.failed {
		return
	}
	mods := mergeVars(before, liveEnvs([]map[*types.Var]value{presentEnv, absentEnv}, []bool{presentEsc, absentEsc})...)
	absentPos := s.Body.Rbrace
	if elseBlock != nil {
		absentPos = elseBlock.Rbrace
	}
	if !presentEsc {
		l.yieldInto(&presentText, presentEnv, mods, "ebpf.yield", s.Body.Rbrace)
	}
	if !absentEsc {
		l.yieldInto(&absentText, absentEnv, mods, "ebpf.yield", absentPos)
	}
	l.env = before
	head, typeList, base := l.resultHead(mods, before)
	l.b.WriteString(fmt.Sprintf("%s%sebpf.ref.check %s : !ebpf.maybe_ref<%s>%s present {\n%s^present(%s: !ebpf.borrowed<%s>):\n%s%s} absent {\n%s%s}%s\n",
		l.indent, head, ref, val.mlir(), typeList, l.indent, borrow, val.mlir(), presentText, l.indent, absentText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(mods, before, base)
	}
}

func (l *lowerer) isNilCheck(cond ast.Expr, p *types.Var) bool {
	be, ok := cond.(*ast.BinaryExpr)
	if !ok || be.Op != token.NEQ {
		return false
	}
	isP := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && l.a.info.Uses[id] == p
	}
	isNil := func(e ast.Expr) bool { return l.a.info.Types[e].IsNil() }
	return (isP(be.X) && isNil(be.Y)) || (isNil(be.X) && isP(be.Y))
}

func (l *lowerer) rejectUses(n ast.Node, p *types.Var, why string) {
	ast.Inspect(n, func(x ast.Node) bool {
		if id, ok := x.(*ast.Ident); ok && l.a.info.Uses[id] == p {
			l.fail(Rejected, GB005NilCheckShape, id.Pos(), "use of %s outside the checked branch: %s", id.Name, why)
		}
		return true
	})
}

// --- expressions ---

// constant turns a constant into an arith.constant of type t.
func (l *lowerer) constant(c constant.Value, t vtype) value {
	v := l.val()
	if t.isBool {
		l.emit("%s = arith.constant %t", v, constant.BoolVal(c)) // an i1 attribute is written without a type
		return value{v, t}
	}
	lit, ok := constLiteral(c, IntType{Bits: t.bits, Signed: t.signed})
	if !ok {
		// Callers must check the range (expr stops it first with GB001). Reaching here is a frontend bug — never silently use a different value.
		l.fail(Unknown, GB015InternalEmitter, token.NoPos, "internal: constant %s does not fit %s in %s — this is a gobpf frontend bug, please report it", c.ExactString(), t.mlir(), l.name)
		lit = "0" // not emitted, since l.failed
	}
	l.emit("%s = arith.constant %s : %s", v, lit, t.mlir())
	return value{v, t}
}

// expr turns an expression into a value. want is the context type (decides the type of untyped constants — nil means the go/types type).
func (l *lowerer) expr(e ast.Expr, want *vtype) (value, bool) {
	defer l.at(e.Pos())()
	if len(l.resvVars) > 0 && l.resvUse(e) { // reading or passing the reserved event
		return value{}, false
	}
	if v, ok, handled := l.urbField(e); handled { // a field of the drain callback's sample
		return v, ok
	}
	tv := l.a.info.Types[e]
	if tv.Value != nil {
		t, ok := goType(tv.Type)
		if want != nil && (!ok || isUntyped(tv.Type)) {
			t, ok = *want, true
		}
		if !ok {
			l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "constant of type %s is not supported", tv.Type)
			return value{}, false
		}
		if !t.isBool {
			if _, fits := constLiteral(tv.Value, IntType{Bits: t.bits, Signed: t.signed}); !fits {
				l.fail(Rejected, GB001UnsupportedConstruct, e.Pos(), "constant %s does not fit %s", tv.Value.ExactString(), t.mlir())
				return value{}, false
			}
		}
		return l.constant(tv.Value, t), true
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		return l.expr(e.X, want)
	case *ast.Ident:
		v := l.localVar(e, false)
		if v != nil {
			if l.borrowOf(v) != nil {
				l.fail(Rejected, GB005NilCheckShape, e.Pos(), "the checked pointer %s may only be dereferenced (`*%s`)", e.Name, e.Name)
				return value{}, false
			}
			val, ok := l.env[v]
			if !ok {
				if _, isPtr := v.Type().(*types.Pointer); isPtr {
					l.fail(Rejected, GB005NilCheckShape, e.Pos(), "%s is used outside its `%s != nil` branch", e.Name, e.Name)
					return value{}, false
				}
				l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "variable %s has no value here", e.Name)
				return value{}, false
			}
			return val, true
		}
		l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "identifier %s is not a local variable or constant of the supported subset", e.Name)
		return value{}, false
	case *ast.StarExpr:
		if id, ok := e.X.(*ast.Ident); ok {
			pv, _ := l.a.info.Uses[id].(*types.Var)
			if c := l.borrowOf(pv); c != nil {
				if c.rec != nil {
					l.fail(Unknown, GB016SharedABIShape, e.Pos(), "*%s reads the whole record %s — read its fields (%s.F) instead (record values are outside the subset)", id.Name, c.rec.Record.Symbol, id.Name)
					return value{}, false
				}
				v := l.val()
				l.emit("%s = ebpf.ref.load %s : !ebpf.borrowed<%s> -> %s", v, c.borrow, c.elem.mlir(), c.elem.mlir())
				return value{v, c.elem}, true
			}
			if pv != nil {
				l.fail(Rejected, GB005NilCheckShape, e.Pos(), "*%s outside the `%s != nil` branch", id.Name, id.Name)
				return value{}, false
			}
		}
		l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "dereference is only supported for the checked pointer of a Lookup")
		return value{}, false
	case *ast.SelectorExpr, *ast.IndexExpr:
		if v, ok, handled := l.tpEventField(e); handled { // a tracepoint event field
			return v, ok
		}
		if v, ok, handled := l.kptrField(e); handled { // a kernel struct field
			return v, ok
		}
		if d, ok, handled := l.dynField(e); handled {
			if !ok {
				return value{}, false
			}
			return l.dynLoad(d), true
		}
		if c, path, t, ok, handled := l.fieldPath(e); handled {
			if !ok {
				return value{}, false
			}
			return l.fieldLoad(c, path, t), true
		}
	case *ast.UnaryExpr:
		return l.unary(e)
	case *ast.BinaryExpr:
		t, ok := goType(tv.Type)
		if !ok {
			l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "operands of type %s are not supported (integers and bool)", tv.Type)
			return value{}, false
		}
		if e.Op == token.LAND || e.Op == token.LOR {
			return l.logical(e)
		}
		lt, _ := goType(l.a.info.Types[e.X].Type)
		if isUntyped(l.a.info.Types[e.X].Type) {
			rt, _ := goType(l.a.info.Types[e.Y].Type)
			lt = rt
		}
		x, ok := l.expr(e.X, &lt)
		if !ok {
			return value{}, false
		}
		return l.binary(e.OpPos, e.Op, x, e.Y, t)
	case *ast.CallExpr:
		if l.a.info.Types[e.Fun].IsType() {
			return l.conversion(e)
		}
		if callee := l.subprogramCallee(e); callee != nil {
			return l.callSubprogram(e, callee)
		}
		if v, ok, handled := l.windowLoad(e); handled {
			return v, ok
		}
		if v, ok, handled := l.taskInfo(e); handled {
			return v, ok
		}
		if v, ok, handled := l.fexitRet(e); handled {
			return v, ok
		}
		if v, ok, handled := l.kprobeArg(e); handled {
			return v, ok
		}
		if v, ok, handled := l.rawTPArg(e); handled {
			return v, ok
		}
		if v, ok, handled := l.tpBufLoad(e); handled { // raw_tp_writable's Buffer
			return v, ok
		}
		if v, ok, handled := l.urbDrain(e); handled { // user_ringbuf's Drain
			return v, ok
		}
		if v, ok, handled := l.syscallLoad(e); handled { // syscall ctx reads
			return v, ok
		}
		if v, ok, handled := l.extArg(e); handled { // arguments of the function an ext replaces
			return v, ok
		}
		if v, ok, handled := l.ctxFieldRead(e); handled { // socket and cgroup context fields
			return v, ok
		}
		if v, ok, handled := l.samplePeriod(e); handled { // perf_event's sample_period
			return v, ok
		}
		if v, ok, handled := l.sessionRead(e); handled { // fsession's IsReturn / Cookie
			return v, ok
		}
		if v, ok, handled := l.iterSeqNum(e); handled { // iter's SeqNum (Seq only in an if init statement)
			return v, ok
		}
		if v, ok, handled := l.nfRead(e); handled { // netfilter state / skb kfield reads
			return v, ok
		}
		if v, ok, handled := l.flowKeysRead(e); handled { // flow_dissector flow_keys reads
			return v, ok
		}
		if v, ok, handled := l.sysctlSet(e); handled { // cgroup_sysctl's SetNewValue
			return v, ok
		}
		if v, ok, handled := l.seqWrite(e); handled { // SeqFile.Write
			return v, ok
		}
		if l.sysCallExpr(e) { // SysBpf / SysClose only as top-level assignment statements
			return value{}, false
		}
		if v, ok, handled := l.probeTargetIndex(e); handled { // the function index of a multi probe
			return v, ok
		}
		if l.tpEventCall(e) {
			if l.tpEventPlace(e) {
				l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.Event() is not a value — read a tagged field in place: ctx.Event().F (each read is one tracepoint field load)")
			}
			return value{}, false
		}
		if v, ok, handled := l.stackPerfCall(e); handled {
			return v, ok
		}
		if v, ok, handled := l.timerCall(e); handled {
			return v, ok
		}
		if op := l.callOp(e); op == "tp_arg_int" || op == "fentry_arg" || op == "fentry_arg_int" {
			if op == "fentry_arg" {
				l.fail(Rejected, GB005NilCheckShape, e.Pos(), "bpf.FentryArg returns a pointer that may be NULL — read it only as `if p := bpf.FentryArg[T](ctx, i); p != nil { … }`")
			} else if op == "fentry_arg_int" {
				l.fail(Rejected, GB027KernelTypeShape, e.Pos(), "bpf.FentryArgInt must be a top-level statement of the fentry program body, `x := bpf.FentryArgInt[T](ctx, i)`")
			} else {
				l.fail(Rejected, GB027KernelTypeShape, e.Pos(), "bpf.TPArgInt must be a top-level statement of the tp_btf program body, `x := bpf.TPArgInt[T](ctx, i)`")
			}
			return value{}, false
		}
		switch l.callOp(e) {
		case "lsm_arg":
			l.fail(Rejected, GB005NilCheckShape, e.Pos(), "bpf.LSMArg returns a pointer that may be NULL — read it only as `if p := bpf.LSMArg[T](ctx, i); p != nil { … }`")
			return value{}, false
		case "structops_arg":
			l.fail(Rejected, GB005NilCheckShape, e.Pos(), "bpf.StructOpsArg returns a pointer that may be NULL — use it only as `if sk := bpf.StructOpsArg[T](ctx, 0); sk != nil { … }`")
			return value{}, false
		case "structops_arg_int":
			l.fail(Rejected, GB027KernelTypeShape, e.Pos(), "bpf.StructOpsArgInt must be a top-level statement of the struct_ops program body, `x := bpf.StructOpsArgInt[T](ctx, i)`")
			return value{}, false
		case "ksyscall_arg":
			l.fail(Rejected, GB008ProgramShape, e.Pos(), "bpf.KsyscallArg must be a top-level statement of the ksyscall program body, `x := bpf.KsyscallArg[T](ctx, n)`")
			return value{}, false
		case "lsm_arg_int":
			l.fail(Rejected, GB027KernelTypeShape, e.Pos(), "bpf.LSMArgInt must be a top-level statement of the lsm program body, `x := bpf.LSMArgInt[T](ctx, i)`")
			return value{}, false
		case "fmod_ret_arg_int":
			l.fail(Rejected, GB027KernelTypeShape, e.Pos(), "bpf.FmodRetArgInt must be a top-level statement of the fmod_ret program body, `x := bpf.FmodRetArgInt[T](ctx, i)`")
			return value{}, false
		case "lsm_deny":
			l.fail(Rejected, GB001UnsupportedConstruct, e.Pos(), "bpf.LSMDeny may only be the returned value of a lsm program (`return bpf.LSMDeny(errno)` — or the A / B of `if c { return A }; return B`)")
			return value{}, false
		}
		if l.callOp(e) == "tp_arg" {
			l.fail(Rejected, GB027KernelTypeShape, e.Pos(), "bpf.TPArg must be a top-level statement of the tp_btf program body, `p := bpf.TPArg[T](ctx, i)` (or `_ = bpf.TPArg[T](ctx, i)`)")
			return value{}, false
		}
		if l.callOp(e) == "with_lock" {
			l.fail(Rejected, GB026LockTimerShape, e.Pos(), "bpf.WithLock is a statement (it returns nothing)")
			return value{}, false
		}
		if call, isUS := l.uprobeStrCall(e); isUS { // a user string only as the second argument of OutputStr
			l.fail(Rejected, GB008ProgramShape, call.Pos(), "bpf.UprobeStr may only be written in place as the second argument of R.OutputStr / R.OutputStrOrDiscard (a user string is not a value — it is read into the event by the helper)")
			return value{}, false
		}
		if op := l.adjustOp(e); op != "" {
			return l.adjust(e, op)
		}
		if v, ok, handled := l.globalCall(e, true); handled {
			return v, ok
		}
		if m, en, _, known := l.mapMethod(e); m != nil && known && en.side != sideUser {
			if _, isStatus := statusOps[en.op]; isStatus {
				return l.statusCall(e, m, en)
			}
			if en.op == "output" {
				return l.output(e, m, true) // the result (bool) is used — if_reserved -> i8
			}
		}
		if _, isRedirect := l.redirectOp(e); isRedirect {
			l.fail(Rejected, GB008ProgramShape, e.Pos(), "ctx.Redirect / RedirectIf is a terminator — write it as the program's last statement `return ctx.Redirect(ifindex)` (its value is the requested action, not a delivery result)")
			return value{}, false
		}
		if m, _, _, _ := l.mapMethod(e); m != nil {
			l.fail(Rejected, GB005NilCheckShape, e.Pos(), "%s's methods are statements (Lookup only as `if p := %s.Lookup(k); p != nil`)", m.Symbol, m.Symbol)
			return value{}, false
		}
		l.unsupportedCall(e)
		return value{}, false
	}
	l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "expression %T is not in the supported subset", e)
	return value{}, false
}

func isUntyped(t types.Type) bool {
	b, ok := t.(*types.Basic)
	return ok && b.Info()&types.IsUntyped != 0
}

func (l *lowerer) unary(e *ast.UnaryExpr) (value, bool) {
	t, ok := goType(l.a.info.Types[e].Type)
	if !ok {
		l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "unary %s on type %s is not supported", e.Op, l.a.info.Types[e].Type)
		return value{}, false
	}
	x, ok := l.expr(e.X, &t)
	if !ok {
		return value{}, false
	}
	switch e.Op {
	case token.ADD:
		return x, true
	case token.SUB:
		z := l.constant(constant.MakeInt64(0), t)
		r := l.val()
		l.emit("%s = arith.subi %s, %s : %s", r, z.name, x.name, t.mlir())
		return value{r, t}, true
	case token.XOR, token.NOT:
		var ones value
		if t.isBool {
			ones = l.constant(constant.MakeBool(true), t)
		} else {
			ones = l.constant(constant.MakeInt64(-1), vtype{bits: t.bits, signed: true})
		}
		r := l.val()
		l.emit("%s = arith.xori %s, %s : %s", r, x.name, ones.name, t.mlir())
		return value{r, t}, true
	}
	l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "unary %s is not supported (no pointers or channels)", e.Op)
	return value{}, false
}

// pure reports whether an expression has no side effects (no calls other than conversions, map operations or packet reads — for the right side of && / ||).
func (l *lowerer) pure(e ast.Expr) bool {
	ok := true
	ast.Inspect(e, func(n ast.Node) bool {
		if c, isCall := n.(*ast.CallExpr); isCall && !l.a.info.Types[c.Fun].IsType() {
			ok = false
		}
		return ok
	})
	return ok
}

func (l *lowerer) logical(e *ast.BinaryExpr) (value, bool) {
	bt := vtype{isBool: true}
	x, ok := l.expr(e.X, &bt)
	if !ok {
		return value{}, false
	}
	if !l.pure(e.Y) {
		return l.shortCircuit(e, x) // with a call on the right, the right side goes into a conditional region (Go short-circuiting — the right side is not evaluated)
	}
	y, ok := l.expr(e.Y, &bt)
	if !ok {
		return value{}, false
	}
	op := "arith.andi"
	if e.Op == token.LOR {
		op = "arith.ori"
	}
	r := l.val()
	l.emit("%s = %s %s, %s : i1", r, op, x.name, y.name)
	return value{r, bt}, true
}

// binary lowers x op y (y is an expression). t is the result type (bool for comparisons).
func (l *lowerer) binary(pos token.Pos, op token.Token, x value, ye ast.Expr, t vtype) (value, bool) {
	// shift: the count is a constant with 0 ≤ count < width (GB012).
	if op == token.SHL || op == token.SHR {
		tv := l.a.info.Types[ye]
		if tv.Value == nil {
			l.fail(Rejected, GB012IntegerRule, ye.Pos(), "shift count must be a constant (variable shift counts are outside the subset)")
			return value{}, false
		}
		n, exact := constant.Int64Val(constant.ToInt(tv.Value))
		if !exact || n < 0 || n >= int64(x.t.bits) {
			l.fail(Rejected, GB012IntegerRule, ye.Pos(), "shift count %s is outside [0, %d) for %s (Go gives 0 or the sign fill, arith gives poison)", tv.Value.ExactString(), x.t.bits, x.t.mlir())
			return value{}, false
		}
		c := l.constant(constant.MakeInt64(n), x.t)
		name := "arith.shli"
		if op == token.SHR {
			name = "arith.shrui"
			if x.t.signed {
				name = "arith.shrsi"
			}
		}
		r := l.val()
		l.emit("%s = %s %s, %s : %s", r, name, x.name, c.name, x.t.mlir())
		return value{r, x.t}, true
	}
	if op == token.QUO || op == token.REM {
		tv := l.a.info.Types[ye]
		if tv.Value == nil {
			l.fail(Rejected, GB012IntegerRule, ye.Pos(), "the divisor must be a non-zero constant (arith's division by zero is undefined behaviour)")
			return value{}, false
		}
		n, exact := constant.Int64Val(constant.ToInt(tv.Value))
		if x.t.signed && exact && n == -1 {
			l.fail(Rejected, GB012IntegerRule, ye.Pos(), "a signed division by the constant -1 is rejected (MinInt / -1 — arith.divsi is undefined behaviour, Go gives MinInt)")
			return value{}, false
		}
		if x.t.signed && exact && !isPow2Magnitude(n) {
			return l.signedDivByConst(op, x, n), true
		}
	}
	y, ok := l.expr(ye, &x.t)
	if !ok {
		return value{}, false
	}
	if y.t != x.t {
		l.fail(Unknown, GB001UnsupportedConstruct, pos, "internal: operand types differ (%s, %s)", x.t.mlir(), y.t.mlir())
		return value{}, false
	}
	r := l.val()
	ty := x.t.mlir()
	if pred, isCmp := cmpPredicate(op, x.t.signed); isCmp {
		l.emit("%s = arith.cmpi %s, %s, %s : %s", r, pred, x.name, y.name, ty)
		return value{r, vtype{isBool: true}}, true
	}
	var name string
	switch op {
	case token.ADD:
		name = "arith.addi"
	case token.SUB:
		name = "arith.subi"
	case token.MUL:
		name = "arith.muli"
	case token.AND:
		name = "arith.andi"
	case token.OR:
		name = "arith.ori"
	case token.XOR:
		name = "arith.xori"
	case token.QUO:
		name = map[bool]string{false: "arith.divui", true: "arith.divsi"}[x.t.signed]
	case token.REM:
		name = map[bool]string{false: "arith.remui", true: "arith.remsi"}[x.t.signed]
	case token.AND_NOT:
		ones := l.constant(constant.MakeInt64(-1), vtype{bits: x.t.bits, signed: true})
		ny := l.val()
		l.emit("%s = arith.xori %s, %s : %s", ny, y.name, ones.name, ty)
		l.emit("%s = arith.andi %s, %s : %s", r, x.name, ny, ty)
		return value{r, x.t}, true
	default:
		l.fail(Unknown, GB001UnsupportedConstruct, pos, "operator %s is not supported", op)
		return value{}, false
	}
	l.emit("%s = %s %s, %s : %s", r, name, x.name, y.name, ty)
	return value{r, t}, true
}

func cmpPredicate(op token.Token, signed bool) (string, bool) {
	u := map[token.Token]string{token.EQL: "eq", token.NEQ: "ne", token.LSS: "ult", token.LEQ: "ule", token.GTR: "ugt", token.GEQ: "uge"}
	s := map[token.Token]string{token.EQL: "eq", token.NEQ: "ne", token.LSS: "slt", token.LEQ: "sle", token.GTR: "sgt", token.GEQ: "sge"}
	if signed {
		p, ok := s[op]
		return p, ok
	}
	p, ok := u[op]
	return p, ok
}

// conversion lowers an integer → integer conversion T(x).
func (l *lowerer) conversion(e *ast.CallExpr) (value, bool) {
	if v, ok, handled := l.kprobePtrConv(e); handled { // uint64(bpf.KprobeArg[uintptr](ctx, n))
		return v, ok
	}
	to, ok := goType(l.a.info.Types[e].Type)
	if !ok || to.isBool || len(e.Args) != 1 {
		l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "conversion to %s is not supported (integers only)", l.a.info.Types[e].Type)
		return value{}, false
	}
	from, ok := goType(l.a.info.Types[e.Args[0]].Type)
	if !ok || from.isBool {
		l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "conversion from %s is not supported (integers only)", l.a.info.Types[e.Args[0]].Type)
		return value{}, false
	}
	if isUntyped(l.a.info.Types[e.Args[0]].Type) {
		from = to
	}
	x, ok := l.expr(e.Args[0], &from)
	if !ok {
		return value{}, false
	}
	switch {
	case to.bits == x.t.bits:
		return value{x.name, to}, true
	case to.bits < x.t.bits:
		r := l.val()
		l.emit("%s = arith.trunci %s : %s to %s", r, x.name, x.t.mlir(), to.mlir())
		return value{r, to}, true
	default:
		op := "arith.extui"
		if x.t.signed { // extend by the source type's signedness (Go conversion semantics)
			op = "arith.extsi"
		}
		r := l.val()
		l.emit("%s = %s %s : %s to %s", r, op, x.name, x.t.mlir(), to.mlir())
		return value{r, to}, true
	}
}

// --- subprogram calls ---

func (l *lowerer) subprogramCallee(call *ast.CallExpr) *Subprogram {
	id, ok := call.Fun.(*ast.Ident)
	if !ok {
		return nil
	}
	fn := l.a.samePkgFunc(id)
	if fn == nil {
		return nil
	}
	return l.a.subByObj[fn]
}

func (l *lowerer) callSubprogram(call *ast.CallExpr, s *Subprogram) (value, bool) {
	if !s.ok {
		l.failed = true // shape errors were already reported on the subprogram side
		return value{}, false
	}
	if !l.checkCallInLoop(call, s) { // path rules for calls inside loops (callloop.go)
		return value{}, false
	}
	var names, typs []string
	for i, arg := range call.Args {
		if s.ctx != nil && i == 0 { // the caller's context (the program ctx, or forwarding the ctx of a callee that took the context)
			id, _ := ast.Unparen(arg).(*ast.Ident)
			if id == nil || l.ctxVar == nil || l.a.info.Uses[id] != l.ctxVar {
				l.fail(Rejected, GB013SubprogramShape, arg.Pos(), "the context argument of %s must be the calling program's context parameter (or the caller's own context parameter, forwarded) — %s is not", s.Symbol, types.ExprString(arg))
				return value{}, false
			}
			names = append(names, "%ctx")
			typs = append(typs, fmt.Sprintf("!ebpf.ctx<%q>", s.ctx.Kind))
			continue
		}
		if s.win != nil && s.win.idx == i { // the window of the caller's Check (resolveWinParams checked the length and shape)
			id, _ := ast.Unparen(arg).(*ast.Ident)
			wv, _ := l.a.info.Uses[id].(*types.Var)
			if id == nil || wv == nil {
				l.failed = true
				return value{}, false
			}
			win, ok := l.liveWindow(id, wv) // w outside the branch is GB005, a stale w after adjust is GB025
			if !ok {
				return value{}, false
			}
			names = append(names, win.name)
			typs = append(typs, fmt.Sprintf("!ebpf.pkt_window<%d>", win.n))
			continue
		}
		if pp := s.ptrs[i]; pp != nil { // a borrowed map value argument
			if pp.kind == "maybe_ref" {
				lc, _ := ast.Unparen(arg).(*ast.CallExpr)
				if lc == nil {
					l.failed = true // resolvePtrParams already reported it
					return value{}, false
				}
				m, _, _, known := l.mapMethod(lc)
				if !known {
					l.failed = true // resolvePtrParams already reported the shape error
					return value{}, false
				}
				ref, ok := l.emitLookup(m, lc)
				if !ok {
					return value{}, false
				}
				names = append(names, ref)
			} else {
				id, _ := ast.Unparen(arg).(*ast.Ident)
				var c *checkedRef
				if id != nil {
					uv, _ := l.a.info.Uses[id].(*types.Var)
					c = l.borrowOf(uv)
				}
				if c == nil {
					l.failed = true // resolvePtrParams already reported it (an argument that is not a checked borrow)
					return value{}, false
				}
				names = append(names, c.borrow)
			}
			typs = append(typs, pp.mlirType())
			continue
		}
		t := s.params[i]
		v, ok := l.expr(arg, &t)
		if !ok {
			return value{}, false
		}
		v = l.toCarrier(v)
		names = append(names, v.name)
		typs = append(typs, v.t.mlir())
	}
	r := l.val()
	rt := s.result.carrier()
	l.emit("%s = ebpf.call @%s(%s) : (%s) -> %s", r, s.Symbol, strings.Join(names, ", "), strings.Join(typs, ", "), rt.mlir())
	return l.fromCarrier(r, s.result), true
}

// constLiteral turns a constant into a decimal literal of t's width (false if out of range).
func constLiteral(c constant.Value, t IntType) (string, bool) {
	c = constant.ToInt(c)
	if c.Kind() != constant.Int {
		return "", false
	}
	if t.Signed {
		v, exact := constant.Int64Val(c)
		if !exact {
			return "", false
		}
		lo, hi := int64(-1)<<(t.Bits-1), int64(1)<<(t.Bits-1)-1
		if t.Bits == 64 {
			lo, hi = -1<<63, 1<<63-1
		}
		if v < lo || v > hi {
			return "", false
		}
		return fmt.Sprint(v), true
	}
	if constant.Sign(c) < 0 {
		// A negative constant for an unsigned type: go/types rejects it, but internal constants such as -1 for ^0 (for xori) are written as all bits of the width
		v, exact := constant.Int64Val(c)
		if !exact || v < -1<<(t.Bits-1) {
			return "", false
		}
		return fmt.Sprint(v), true
	}
	v, exact := constant.Uint64Val(c)
	if !exact || (t.Bits < 64 && v >= uint64(1)<<t.Bits) {
		return "", false
	}
	// arith.constant is signless — values with the top bit set are written as two's-complement negatives (the MLIR integer attribute range).
	if t.Bits == 64 && v >= 1<<63 {
		return fmt.Sprint(int64(v)), true
	}
	if t.Bits < 64 && v >= uint64(1)<<(t.Bits-1) {
		return fmt.Sprint(int64(v) - int64(1)<<t.Bits), true
	}
	return fmt.Sprint(v), true
}

// ret turns the final `return <a bpf.XDPAction constant>` into ebpf.verdict.
func (l *lowerer) ret(r *ast.ReturnStmt) {
	defer l.at(r.Pos())()
	k := l.progKind
	if len(r.Results) != 1 {
		l.fail(Rejected, GB001UnsupportedConstruct, r.Pos(), "program must return exactly one %s", k.returnForm())
		return
	}
	// sched_cls redirect (`return ctx.Redirect(ifindex)` / `return ctx.RedirectIf(ok, ifindex, bpf.TCPass)`).
	if call, isCall := r.Results[0].(*ast.CallExpr); isCall {
		if op, isRedirect := l.redirectOp(call); isRedirect {
			l.redirect(call, op)
			return
		}
		if m, op, isRM := l.redirectMapCall(call); isRM { // devmap redirect_map
			l.redirectMap(call, m, op)
			return
		}
		if m, op, isSK := l.skRedirectCall(call); isSK { // sockmap / sockhash sk.redirect
			l.skRedirect(call, m, op)
			return
		}
	}
	if k.IntRet != nil && k.IntRetExpr { // fmod_ret returns a computed i32 (ebpf.return)
		if v, ok := l.intRetExpr(r.Results[0], false); ok {
			l.emit("ebpf.return %s : %s", v.name, l.retVType().mlir()) // for ext, the result width of the replaced function
		}
		return
	}
	if k.IntRet != nil { // lsm returns an i32 constant (ebpf.return)
		if n, ok := l.intRet(r.Results[0]); ok {
			c := l.val()
			l.emit("%s = arith.constant %d : i32", c, n)
			l.emit("ebpf.return %s : i32", c)
		}
		return
	}
	if name, ok := l.verdictName(r.Results[0]); ok {
		l.emit("ebpf.verdict %q", name)
	}
}

// intRet returns the constant return value of an IntRet kind (lsm): `bpf.LSMAllow`, `bpf.LSMDeny(<constant 1..4095>)`, or a bpf.LSMRet constant in range.
// GB006 if not a constant, GB001 if out of range.
func (l *lowerer) intRet(e ast.Expr) (int64, bool) {
	k := l.progKind
	lo, hi := k.IntRet[0], k.IntRet[1]
	if call, ok := ast.Unparen(e).(*ast.CallExpr); ok && l.callOp(call) == "lsm_deny" {
		tv := l.a.info.Types[call.Args[0]]
		n, exact := int64(0), false
		if tv.Value != nil {
			n, exact = constant.Int64Val(constant.ToInt(tv.Value))
		}
		if tv.Value == nil {
			l.fail(Rejected, GB006NonConstant, call.Args[0].Pos(), "the errno of bpf.LSMDeny must be a constant 1..%d (the program returns a constant — to choose it by a condition, end the body with `if c { return A }; return B`)", -lo)
			return 0, false
		}
		if !exact || n < 1 || n > -lo {
			l.fail(Rejected, GB001UnsupportedConstruct, call.Args[0].Pos(), "the errno of bpf.LSMDeny must be 1..%d (got %s — the %s program returns −errno, and 0 is bpf.LSMAllow)", -lo, tv.Value.ExactString(), k.Kind)
			return 0, false
		}
		return -n, true
	}
	tv := l.a.info.Types[e]
	consts, allowed := "bpf.LSMAllow or bpf.LSMDeny(errno) with a constant errno", "the kernel allows 0 or a negative errno"
	if k.Kind == "kprobe_session" {
		consts, allowed = "bpf.KprobeSessionRun or bpf.KprobeSessionSkipReturn", "0 runs the return probe, 1 skips it"
	}
	if tv.Value == nil {
		l.fail(Rejected, GB006NonConstant, e.Pos(), "the returned value of the %s program must be a constant (%s) — to choose it by a condition, end the body with `if c { return A }; return B`", k.Kind, consts)
		return 0, false
	}
	n, exact := constant.Int64Val(tv.Value)
	if !exact || n < lo || n > hi {
		l.fail(Rejected, GB001UnsupportedConstruct, e.Pos(), "the %s program returns %s, outside %d..%d (%s)", k.Kind, tv.Value.ExactString(), lo, hi, allowed)
		return 0, false
	}
	return n, true
}

// intRetExpr lowers the i32 return expression of an IntRetExpr kind (fmod_ret; Go type checking guarantees bpf.FmodRet). inSelect is the A / B of the body's final
// `if c { return A }; return B` — both are evaluated before the condition, so **only expressions with no side effects or traps** (identifiers, constants, conversions, + − * & | ^,
// unary −, parentheses) are accepted; others (calls, division, shifts etc.) get GB001 pointing to computing `r := …` first.
func (l *lowerer) intRetExpr(e ast.Expr, inSelect bool) (value, bool) {
	if inSelect {
		var bad ast.Node
		ast.Inspect(e, func(n ast.Node) bool {
			if bad != nil {
				return false
			}
			switch x := n.(type) {
			case nil, *ast.Ident, *ast.BasicLit, *ast.ParenExpr, *ast.SelectorExpr:
			case *ast.UnaryExpr:
				if x.Op != token.SUB && x.Op != token.ADD {
					bad = x
				}
			case *ast.BinaryExpr:
				switch x.Op {
				case token.ADD, token.SUB, token.MUL, token.AND, token.OR, token.XOR:
				default:
					bad = x
				}
			case *ast.CallExpr:
				if tv := l.a.info.Types[x.Fun]; !tv.IsType() {
					bad = x
				}
			default:
				bad = x
			}
			return true
		})
		if bad != nil {
			l.fail(Rejected, GB001UnsupportedConstruct, bad.Pos(), "the A / B of the final `if c { return A }; return B` of the %s program are both evaluated before the choice, so they may only use variables, constants, conversions and + − * & | ^ — compute other values into a variable first (`r := …; if c { return r }`)", l.progKind.Kind)
			return value{}, false
		}
	}
	want := l.retVType()
	v, ok := l.expr(e, &want)
	if !ok {
		return value{}, false
	}
	return v, true
}

// verdictName returns the spelling of a verdict constant expression (GB006 if not a constant, GB001 if not a verdict of the kind).
func (l *lowerer) verdictName(e ast.Expr) (string, bool) {
	k := l.progKind
	tv := l.a.info.Types[e]
	if tv.Value == nil {
		first := map[string]string{"TCAction": "TCPass", "CgroupAction": "CgroupAllow", "SocketFilterAction": "SocketKeep"}[k.Action]
		if first == "" {
			first = "XDPPass"
		}
		l.fail(Rejected, GB006NonConstant, e.Pos(), "the returned action must be a constant (bpf.%s, …) — to choose it by a condition, end the body with `if c { return A }; return B`", first)
		return "", false
	}
	n, exact := constant.Int64Val(tv.Value)
	name, known := k.Verdicts[n]
	if !exact || !known {
		l.fail(Rejected, GB001UnsupportedConstruct, e.Pos(), "action %s is not a supported %s verdict (%s)", tv.Value.ExactString(), k.Kind, verdictList(k))
		return "", false
	}
	if name == "deny" && l.prog != nil && allowOnlyHooks[[2]string{k.Kind, l.prog.Attach}] {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "the %s hook %s only allows bpf.CgroupAllow (the kernel restricts its return value to 1)", k.Kind, l.prog.Attach)
		return "", false
	}
	return name, true
}

// verdictList returns the kind's verdict spellings in value order (for diagnostics — xdp is "aborted / drop / pass / tx").
func verdictList(k *ctxKind) string {
	var vals []int64
	for v := range k.Verdicts {
		vals = append(vals, v)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	var names []string
	for _, v := range vals {
		names = append(names, k.Verdicts[v])
	}
	return strings.Join(names, " / ")
}

// redirectOp returns the op if call is Redirect / RedirectIf on the current program's context.
func (l *lowerer) redirectOp(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	e, known := lookupAPI(l.a.info.Uses[sel.Sel])
	if !known || (e.op != "redirect" && e.op != "redirect_if") {
		return "", false
	}
	return e.op, true
}

// redirect emits the sched_cls terminator `ebpf.redirect %ifindex : i32 [when %c else "<verdict>"]` (the return value is the requested action,
// not whether delivery succeeded — a bpf-mlir finding).
func (l *lowerer) redirect(call *ast.CallExpr, op string) {
	sel := call.Fun.(*ast.SelectorExpr)
	if recv, ok := sel.X.(*ast.Ident); !ok || l.a.info.Uses[recv] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "Redirect must be called on the program's context parameter")
		return
	}
	u32 := vtype{bits: 32}
	if op == "redirect" {
		idx, ok := l.expr(call.Args[0], &u32)
		if !ok {
			return
		}
		l.emit("ebpf.redirect %s : i32", idx.name)
		return
	}
	bt := vtype{isBool: true}
	c, ok := l.expr(call.Args[0], &bt)
	if !ok {
		return
	}
	idx, ok := l.expr(call.Args[1], &u32)
	if !ok {
		return
	}
	tv := l.a.info.Types[call.Args[2]]
	var name string
	if tv.Value != nil {
		if n, exact := constant.Int64Val(tv.Value); exact {
			name = l.progKind.Verdicts[n]
		}
	}
	if name == "" {
		l.fail(Rejected, GB006NonConstant, call.Args[2].Pos(), "the otherwise action of RedirectIf must be a constant sched_cls verdict (bpf.TCPass / bpf.TCDrop)")
		return
	}
	l.emit("ebpf.redirect %s : i32 when %s else %q", idx.name, c.name, name)
}

// isPow2Magnitude reports whether the magnitude of n is a power of two (1, 2, 4 … 2^63 — including MinInt).
func isPow2Magnitude(n int64) bool {
	m := uint64(n)
	if n < 0 {
		m = uint64(-(n + 1)) + 1 // the magnitude without overflow, even for MinInt
	}
	return m != 0 && m&(m-1) == 0
}

// signedDivByConst expands signed `x / n` and `x % n` (n a nonzero constant that is not ±2^k) into a magnitude divui / remui plus a sign fixup.
// The eBPF CPU v1 has no signed division, and LLVM cannot expand i64 signed division by a constant divisor (unsupported signed
// division) — the bpf-mlir v0.8.0 contract (arith_contract.md) also limits divsi / remsi divisors to ±2^k. The same rule for every width (lowering does not vary by width):
//
//	ax = x < 0 ? 0 − x : x        (the MinInt magnitude 2^(w−1) is correct as unsigned)
//	/ : q = ax /u |n| — 0 − q if x and n differ in sign (Go `/` truncates toward 0)
//	% : r = ax %u |n| — 0 − r if x < 0 (Go `%` takes the dividend's sign)
func (l *lowerer) signedDivByConst(op token.Token, x value, n int64) value {
	ty := x.t.mlir()
	zero := l.constant(constant.MakeInt64(0), x.t)
	mag := n
	if mag < 0 {
		mag = -mag // n is not ±2^k — MinInt (a power of two) never comes here
	}
	d := l.constant(constant.MakeInt64(mag), x.t)
	neg, nx, ax := l.val(), l.val(), l.val()
	l.emit("%s = arith.cmpi slt, %s, %s : %s", neg, x.name, zero.name, ty)
	l.emit("%s = arith.subi %s, %s : %s", nx, zero.name, x.name, ty)
	l.emit("%s = arith.select %s, %s, %s : %s", ax, neg, nx, x.name, ty)
	u, nu, r := l.val(), l.val(), l.val()
	if op == token.QUO {
		l.emit("%s = arith.divui %s, %s : %s", u, ax, d.name, ty)
	} else {
		l.emit("%s = arith.remui %s, %s : %s", u, ax, d.name, ty)
	}
	l.emit("%s = arith.subi %s, %s : %s", nu, zero.name, u, ty)
	if op == token.QUO && n < 0 {
		l.emit("%s = arith.select %s, %s, %s : %s", r, neg, u, nu, ty) // negative divisor: positive if the dividend is negative
	} else {
		l.emit("%s = arith.select %s, %s, %s : %s", r, neg, nu, u, ty)
	}
	return value{r, x.t}
}

// lowerPanicHook is set only by tests (nil otherwise — tests confirm that a lowering panic becomes GB015).
var lowerPanicHook func(name string)

// guardLowering turns a panic while lowering one function into GB015 (a frontend internal error) at that function's position (previously the
// zero value of `var ok bool` panicked and took down the whole process). Lowering and diagnostics of other functions continue. No output is produced since there is an error.
func (a *analyzer) guardLowering(name string, pos token.Pos, lower func()) {
	defer func() {
		if r := recover(); r != nil {
			a.report(Unknown, GB015InternalEmitter, pos, []string{name}, "internal: the frontend panicked while lowering %s: %v — this is a gobpf frontend bug, please report it with the Go source", name, r)
		}
	}()
	if lowerPanicHook != nil {
		lowerPanicHook(name)
	}
	lower()
}

// isVerdictIf reports whether s is a conditional verdict: the arm is the single statement `return <one expression>`. withElse is the shape with `else { return B }`,
// false the shape without else (paired with a following `return B`). Other shapes (other statements in the arm, else if) are false — lowered as an ordinary if, where a
// return in the arm stops with GB001 as before.
func (l *lowerer) isVerdictIf(s *ast.IfStmt, withElse bool) bool {
	if l.isLookupIf(s) || l.isCheckIf(s) {
		return false // the arms of `if p := M.Lookup(k); p != nil` and `if w, ok := ctx.Check(…); ok` are check regions — a return in them stays GB001
	}
	oneReturn := func(b *ast.BlockStmt) bool {
		if b == nil || len(b.List) != 1 {
			return false
		}
		r, ok := b.List[0].(*ast.ReturnStmt)
		return ok && len(r.Results) == 1
	}
	if !oneReturn(s.Body) {
		return false
	}
	if !withElse {
		return s.Else == nil
	}
	eb, ok := s.Else.(*ast.BlockStmt)
	return ok && oneReturn(eb)
}

// hasTailCall reports whether the body has a top-level TailCall (a conditional verdict in the tail call fallback is out of scope — the existing shape stays).
func (l *lowerer) hasTailCall(stmts []ast.Stmt) bool {
	for _, s := range stmts {
		if call, _ := l.tailCallOp(s); call != nil {
			return true
		}
	}
	return false
}

// verdictIf turns `if c { return A }` and B into ebpf.verdict.if c "A" else "B" (A / B are verdict constants, c is a bool expression — the init statement goes before the if).
func (l *lowerer) verdictIf(s *ast.IfStmt, a, b *ast.ReturnStmt) {
	defer l.at(s.Pos())()
	if s.Init != nil {
		l.stmt(s.Init)
		if l.failed {
			return
		}
	}
	bt := vtype{isBool: true}
	c, ok := l.expr(s.Cond, &bt)
	if !ok {
		return
	}
	if l.progKind.IntRet != nil && l.progKind.IntRetExpr { // fmod_ret: a select of two i32 expressions and ebpf.return
		av, aok := l.intRetExpr(a.Results[0], true)
		if !aok {
			return
		}
		bv, bok := l.intRetExpr(b.Results[0], true)
		if !bok {
			return
		}
		r, ty := l.val(), l.retVType().mlir()
		l.emit("%s = arith.select %s, %s, %s : %s", r, c.name, av.name, bv.name, ty)
		l.emit("ebpf.return %s : %s", r, ty)
		return
	}
	if l.progKind.IntRet != nil { // lsm: a select of two i32 constants and ebpf.return
		an, aok := l.intRet(a.Results[0])
		bn, bok := l.intRet(b.Results[0])
		if !aok || !bok {
			return
		}
		ac, bc, r := l.val(), l.val(), l.val()
		l.emit("%s = arith.constant %d : i32", ac, an)
		l.emit("%s = arith.constant %d : i32", bc, bn)
		l.emit("%s = arith.select %s, %s, %s : i32", r, c.name, ac, bc)
		l.emit("ebpf.return %s : i32", r)
		return
	}
	an, ok := l.verdictName(a.Results[0])
	if !ok {
		return
	}
	bn, ok := l.verdictName(b.Results[0])
	if !ok {
		return
	}
	l.emit("ebpf.verdict.if %s %q else %q", c.name, an, bn)
}

// shortCircuit turns `x && y` / `x || y` with a call on the right into an ebpf.if whose right side is a conditional region (Go semantics: && does not evaluate y if x is false,
// || does not if x is true. Map operations, helpers, global Value, window reads and subprogram calls on the right do not happen):
//
//	x && y  →  %r = ebpf.if %x -> i1 { <y>; ebpf.if.yield %y : i1 } else { %f = arith.constant false; ebpf.if.yield %f : i1 }
//	x || y  →  %r = ebpf.if %x -> i1 { %t = arith.constant true; ebpf.if.yield %t : i1 } else { <y>; ebpf.if.yield %y : i1 }
//
// The region result is i1 directly (since bpf-mlir v0.8.0 — no i8 carrying as in variable merges: it is an expression value, not crossing variables). A pure right side stays
// arith.andi / ori as before (evaluating both has the same meaning — existing outputs are byte-identical). Packet generations are counted per arm and maxed at the merge, as for if statements.
func (l *lowerer) shortCircuit(e *ast.BinaryExpr, x value) (value, bool) {
	bt := vtype{isBool: true}
	gen0 := l.pktGen
	ok := true
	right := l.region(func() {
		y, yok := l.expr(e.Y, &bt)
		if !yok {
			ok = false
			return
		}
		l.emit("ebpf.if.yield %s : i1", y.name)
	})
	genY := l.pktGen
	l.pktGen = gen0
	if !ok {
		return value{}, false
	}
	constArm := l.region(func() {
		c := l.constant(constant.MakeBool(e.Op == token.LOR), bt)
		l.emit("ebpf.if.yield %s : i1", c.name)
	})
	then, els := right, constArm
	if e.Op == token.LOR {
		then, els = constArm, right
	}
	l.armGen(gen0, genY)
	r := l.val()
	l.b.WriteString(fmt.Sprintf("%s%s = ebpf.if %s -> i1 {\n%s%s} else {\n%s%s}%s\n", l.indent, r, x.name, then, l.indent, els, l.indent, l.locSuffix(e.OpPos)))
	return value{r, bt}, true
}
