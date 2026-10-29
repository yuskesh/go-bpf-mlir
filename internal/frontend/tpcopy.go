package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
)

// Tracepoint byte array fields (bpf-mlir's ebpf.tp.field.copy):
//
//	type Rename struct {
//		_   [12]byte
//		Old [16]byte `tp:"oldcomm"`
//	}
//	if q := Last.Lookup(0); q != nil {
//		q.Old = ctx.Event().Old                → ebpf.tp.field.copy %borrow "Old", %ctx "oldcomm" [12] : !ebpf.borrowed<R>, !ebpf.ctx<"tracepoint">
//	}
//	if e, ok := Events.Reserve(); ok {
//		e.Old = ctx.Event().Old                → ebpf.tp.field.copy %res "Old", %ctx "oldcomm" [12] : !ebpf.reservation<R>, !ebpf.ctx<"tracepoint">
//		Events.Submit(e)
//	}
//
// The array is never a value: the N bytes are copied as they are (no NUL handling) into a field of the same Go type (Go's type check forces N and the element type).

// tpFieldCopy lowers `q.F = ctx.Event().G` (G a byte array field of the tracepoint event). handled reports whether the right-hand side is such a field.
func (l *lowerer) tpFieldCopy(s *ast.AssignStmt) bool {
	if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		return false
	}
	sel, ok := ast.Unparen(s.Rhs[0]).(*ast.SelectorExpr)
	if !ok || !l.tpEventCall(sel.X) || l.prog == nil {
		return false
	}
	var f *TPField
	for i := range l.prog.TPFields {
		if l.prog.TPFields[i].GoName == sel.Sel.Name && l.prog.TPFields[i].Arr > 0 {
			f = &l.prog.TPFields[i]
		}
	}
	if f == nil {
		return false
	}
	defer l.at(s.Pos())()
	if !l.tpEventPlace(ast.Unparen(sel.X).(*ast.CallExpr)) {
		return true
	}
	x := types.ExprString(sel)
	if s.Tok != token.ASSIGN {
		l.fail(Rejected, GB008ProgramShape, s.Pos(), "%s can only be copied with `=` into a field of the same type of a checked record", x)
		return true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, s.Pos(), "the copy of the tracepoint array %s may not be inside a loop (bpf-mlir's tp.field.copy is not accepted in a loop)", x)
		return true
	}
	src := func() string { return fmt.Sprintf("%%ctx %q [%d] : ", f.Name, f.Offset) }
	if lhs, isSel := ast.Unparen(s.Lhs[0]).(*ast.SelectorExpr); isSel {
		if v := l.resvOf(lhs.X); v != nil {
			if !l.resvPlace(v, s.Pos(), "copy into a field") {
				return true
			}
			m := l.resv.m
			rf, found := m.Value.Record.fieldByGoName(lhs.Sel.Name)
			if !found || !byteArrayOf(rf.Type, f.Arr) {
				l.fail(Rejected, GB008ProgramShape, lhs.Sel.Pos(), "the destination of the copy of %s must be a [%d]byte / [%d]int8 field of the event %s", x, f.Arr, f.Arr, m.Value.Record.Symbol)
				return true
			}
			l.emit("ebpf.tp.field.copy %s %q, %s!ebpf.reservation<%s>, !ebpf.ctx<\"tracepoint\">", l.resv.res, rf.Name, src(), m.Value.mlir())
			return true
		}
	}
	acc, ok, h := l.walkAccess(s.Lhs[0], true)
	if !h {
		l.fail(Rejected, GB008ProgramShape, s.Lhs[0].Pos(), "the tracepoint array %s can only be copied into a field of a checked record (`if q := M.Lookup(k); q != nil { q.F = %s }` or `if e, ok := R.Reserve(); ok { e.F = %s … }`)", x, x, x)
		return true
	}
	if !ok {
		return true
	}
	if len(acc.vars) > 0 || !byteArrayOf(acc.end, f.Arr) {
		l.fail(Rejected, GB008ProgramShape, s.Lhs[0].Pos(), "the destination of the copy of %s must be a [%d]byte / [%d]int8 field at a constant path of the checked record (got %s)", x, f.Arr, f.Arr, types.ExprString(s.Lhs[0]))
		return true
	}
	l.emit("ebpf.tp.field.copy %s %q, %s%s, !ebpf.ctx<\"tracepoint\">", acc.ref.borrow, acc.path, src(), borrowType(acc.ref))
	return true
}

// byteArrayOf reports whether t is a one-dimensional array of n 8-bit integers.
func byteArrayOf(t SharedABI, n int64) bool {
	return t.Kind == ABIArray && t.Array.Elem.Kind == ABIInt && t.Array.Elem.Int.Bits == 8 && t.Array.Count == uint64(n)
}
