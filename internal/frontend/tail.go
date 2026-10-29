package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"sort"
)

// prog_array and tail calls (bpf-mlir's ebpf.tail_call).
//
// Declaration: `var Stages = bpf.ProgArray{MaxEntries: N}` and a package-level `var _ = bpf.TailSlot(&Stages, <constant>, <xdp program>)`.
// A slot becomes the slots of the schema map (bpf-mlir turns it into a tailslot requirement row — version 7), and gobpf.Load sets it after load.
// The eBPF side: a top-level statement `Stages.TailCall(ctx, i)` / `Stages.TailCallIf(ctx, ok, i, bpf.XDPPass)` of an xdp program body is terminal, and
// the statements after it (up to the final return) are the fallback region.

// TailSlotDecl is the declaration of one prog_array slot.
type TailSlotDecl struct {
	Index   uint64
	Program string
	Pos     token.Position // the position of the bpf.TailSlot call (provenance in the generated file — not in the schema)
}

// PosString returns the position of the declaration.
func (s *TailSlotDecl) PosString() string { return posString(s.Pos) }

// collectProgArray checks and collects prog_array declarations (key / value are fixed to u32).
func (a *analyzer) collectProgArray(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int) {
	u32 := types.Typ[types.Uint32]
	m := &BpfMap{Symbol: obj.Name(), Kind: "prog_array", Pos: a.position(name.Pos()), obj: obj,
		Key: sharedABIOfInt(u32, IntType{32, false}), Value: sharedABIOfInt(u32, IntType{32, false})}
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "prog_array %s needs an initializer bpf.ProgArray{MaxEntries: N} (MaxEntries is required)", obj.Name())
		return
	}
	if !a.mapInit(m, vs.Values[i]) {
		return
	}
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// isTailSlotCall reports whether call is a call of bpf.TailSlot.
func (a *analyzer) isTailSlotCall(call *ast.CallExpr) bool {
	var id *ast.Ident
	switch f := call.Fun.(type) {
	case *ast.Ident:
		id = f
	case *ast.SelectorExpr:
		id = f.Sel
	default:
		return false
	}
	fn, ok := a.info.Uses[id].(*types.Func)
	return ok && fn.Pkg() != nil && fn.Pkg().Path() == bpfPkg && fn.Name() == "TailSlot"
}

// collectTailSlots reads package-level `var _ = bpf.TailSlot(&M, slot, Prog)` and stops bpf.TailSlot elsewhere with GB023
// (inside an eBPF side function it is checkEBPFSide's GB003 — not reported twice). Call it after collectMaps, collectPrograms and computeDomains.
func (a *analyzer) collectTailSlots() {
	accepted := map[*ast.CallExpr]bool{}
	for _, f := range a.files() {
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for _, v := range vs.Values {
					call, ok := v.(*ast.CallExpr)
					if !ok || !a.isTailSlotCall(call) {
						continue
					}
					accepted[call] = true
					if len(vs.Names) != 1 || vs.Names[0].Name != "_" || len(vs.Values) != 1 {
						a.report(Rejected, GB023TailShape, call.Pos(), nil, "a tail-call slot is declared alone as `var _ = bpf.TailSlot(&M, slot, Program)` at package level")
						continue
					}
					a.tailSlot(call)
				}
			}
		}
	}
	for _, f := range a.files() {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				if obj, _ := a.info.Defs[fd.Name].(*types.Func); obj != nil && a.isBPF(obj) {
					continue
				}
			}
			ast.Inspect(d, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok && a.isTailSlotCall(call) && !accepted[call] {
					a.report(Rejected, GB023TailShape, call.Pos(), nil, "bpf.TailSlot is a declaration, not a runtime call: write it as `var _ = bpf.TailSlot(&M, slot, Program)` at package level (gobpf.Load sets the slots)")
				}
				return true
			})
		}
	}
	for _, m := range a.maps {
		sort.Slice(m.Slots, func(i, j int) bool { return m.Slots[i].Index < m.Slots[j].Index })
	}
}

// tailSlot checks the arguments of one declaration and adds it to the map's Slots.
func (a *analyzer) tailSlot(call *ast.CallExpr) {
	bad := func(p token.Pos, format string, args ...any) {
		a.report(Rejected, GB023TailShape, p, nil, format, args...)
	}
	// &M — M is a package-level bpf.ProgArray declaration.
	var m *BpfMap
	if u, ok := call.Args[0].(*ast.UnaryExpr); ok && u.Op == token.AND {
		if id, ok := u.X.(*ast.Ident); ok {
			v, _ := a.info.Uses[id].(*types.Var)
			m = a.mapByObj[v]
			if m == nil && v != nil && isBPFNamed(v.Type(), "ProgArray") && v.Parent() == a.pkg.Types.Scope() {
				return // the declaration shape error is already reported (GB009)
			}
		}
	}
	if m == nil || m.Kind != "prog_array" {
		bad(call.Args[0].Pos(), "the first argument of bpf.TailSlot must be &M for a package-level bpf.ProgArray M")
		return
	}
	// slot — a constant below MaxEntries.
	tv := a.info.Types[call.Args[1]]
	if tv.Value == nil {
		a.report(Rejected, GB006NonConstant, call.Args[1].Pos(), nil, "the slot of bpf.TailSlot must be a constant")
		return
	}
	slot, exact := constUint64(tv)
	if !exact || slot >= m.MaxEntries {
		bad(call.Args[1].Pos(), "slot %s of %s is outside [0, %d) (MaxEntries)", tv.Value.ExactString(), m.Symbol, m.MaxEntries)
		return
	}
	// program — the name of an xdp program function in the same package (a function value).
	var prog *Program
	if id, ok := ast.Unparen(call.Args[2]).(*ast.Ident); ok {
		if fn, ok := a.info.Uses[id].(*types.Func); ok {
			for _, p := range a.programs {
				if p.obj == fn {
					prog = p
				}
			}
		}
	}
	if prog == nil || prog.ProgramType != "xdp" {
		bad(call.Args[2].Pos(), "the program of a tail-call slot must be an xdp program declared in this package, named directly (func(ctx *bpf.XDPContext) bpf.XDPAction)")
		return
	}
	for _, s := range m.Slots {
		if s.Index == slot {
			bad(call.Args[1].Pos(), "slot %d of %s is declared twice (first at %s)", slot, m.Symbol, s.PosString())
			return
		}
	}
	m.Slots = append(m.Slots, &TailSlotDecl{Index: slot, Program: prog.Symbol, Pos: a.position(call.Pos())})
}

// isTailSlotMapArg reports whether `&M` is the first argument of bpf.TailSlot (an exception to taking a map's address on the user side — checkMapVarUse).
func (a *analyzer) isTailSlotMapArg(u *ast.UnaryExpr, call *ast.CallExpr) bool {
	return u.Op == token.AND && a.isTailSlotCall(call) && len(call.Args) == 3 && call.Args[0] == ast.Expr(u)
}

// --- lowering ---

// tailCallOp returns the call and op if the statement is a call of ProgArray.TailCall / TailCallIf.
func (l *lowerer) tailCallOp(s ast.Stmt) (*ast.CallExpr, string) {
	es, ok := s.(*ast.ExprStmt)
	if !ok {
		return nil, ""
	}
	call, ok := es.X.(*ast.CallExpr)
	if !ok {
		return nil, ""
	}
	if op := l.apiOp(call); op == "tail_call" || op == "tail_call_if" {
		return call, op
	}
	return nil, ""
}

// rejectTailCall stops a TailCall that is not at the top level of a program body (called from stmt).
func (l *lowerer) rejectTailCall(call *ast.CallExpr) {
	switch {
	case l.inFallback:
		l.fail(Rejected, GB023TailShape, call.Pos(), "a program makes at most one tail call: the fallback (the statements after TailCall) cannot tail call again (bpf-mlir v0.8.0)")
	case !l.isProg:
		l.fail(Rejected, GB023TailShape, call.Pos(), "TailCall is only available in the program itself, not in a subprogram (the tail call ends the program)")
	default:
		l.fail(Rejected, GB023TailShape, call.Pos(), "TailCall must be a top-level statement of the program body (not inside if, loop or ctx.Check) — the statements after it are the fallback")
	}
}

// tailCall lowers `M.TailCall(ctx, i)` / `M.TailCallIf(ctx, ok, i, else)` and the fallback (rest and the final return) to ebpf.tail_call.
func (l *lowerer) tailCall(call *ast.CallExpr, op string, rest []ast.Stmt, last *ast.ReturnStmt) {
	defer l.at(call.Pos())()
	if l.progKind.Kind != "xdp" {
		l.fail(Rejected, GB023TailShape, call.Pos(), "tail calls are xdp-only (bpf-mlir v0.8.0 — ebpf.tail_call takes an xdp context)")
		return
	}
	m, _, _, _ := l.mapMethod(call)
	if m == nil {
		l.fail(Rejected, GB023TailShape, call.Fun.Pos(), "TailCall must be called on a package-level bpf.ProgArray")
		return
	}
	if id, ok := call.Args[0].(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB023TailShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", opName(op))
		return
	}
	idxArg := call.Args[1]
	if op == "tail_call_if" {
		idxArg = call.Args[2]
	}
	when := ""
	if op == "tail_call_if" {
		bt := vtype{isBool: true}
		c, ok := l.expr(call.Args[1], &bt)
		if !ok {
			return
		}
		tv := l.a.info.Types[call.Args[3]]
		if tv.Value == nil {
			l.fail(Rejected, GB006NonConstant, call.Args[3].Pos(), "the otherwise action of TailCallIf must be a constant (bpf.XDPPass, …)")
			return
		}
		n, exact := constUint64(tv)
		name, known := l.progKind.Verdicts[int64(n)]
		if !exact || !known {
			l.fail(Rejected, GB023TailShape, call.Args[3].Pos(), "action %s is not a supported xdp verdict (%s)", tv.Value.ExactString(), verdictList(l.progKind))
			return
		}
		when = fmt.Sprintf(" when %s else %q", c.name, name)
	}
	it := vtype{bits: 32}
	i, ok := l.expr(idxArg, &it)
	if !ok {
		return
	}
	mt := fmt.Sprintf("!ebpf.map<%q, %s, %s>", m.Kind, m.Key.mlir(), m.Value.mlir())
	l.pktGen++ // packet pointers are invalid after a tail call attempt (kept in one place with the generation rule)
	l.lastAdjust, l.lastAdjustName = call.Pos(), opName(op)
	l.inFallback = true
	fb := l.region(func() {
		l.stmts(rest)
		if !l.failed {
			l.ret(last)
		}
	})
	l.inFallback = false
	if l.failed {
		return
	}
	l.b.WriteString(fmt.Sprintf("%sebpf.tail_call %%ctx, %s[%s] : !ebpf.ctx<%q>, %s, i32%s fallback {\n%s%s}%s\n",
		l.indent, l.mapArgs[m], i.name, l.progKind.Kind, mt, when, fb, l.indent, l.locSuffix(call.Pos())))
}

func opName(op string) string {
	if op == "tail_call_if" {
		return "TailCallIf"
	}
	return "TailCall"
}
