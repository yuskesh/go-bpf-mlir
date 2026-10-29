package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
)

// uprobe user buffers and raw pointers (bpf-mlir's !ebpf.user_buf, user.read and the schema's ptr param).
//
//	//gobpf:uprobe fixture/bfix buf_write
//	func onWrite(ctx *bpf.UprobeContext) {
//		p := uint64(bpf.UprobeArg[uintptr](ctx, 2))                    → ebpf.uprobe.arg %ctx 2 : !ebpf.ctx<"uprobe"> -> i64 (schema ptr)
//		st, n, ok := Ev.OutputBuf(E{P: p}, bpf.UprobeBuf(ctx, 2), int64(bpf.UprobeArg[int32](ctx, 3)))
//	}
//
// OutputBuf reads cnt = max(0, min(n, N)) bytes into the `gobpf:"userbuf"` field (zeroed first — a failed read leaves it all 0) and writes the raw
// status and cnt into the `gobpf:"userbuf_status"` / `gobpf:"userbuf_len"` fields. A user buffer or raw pointer argument is checked against a
// single-level 8-byte DWARF pointer at generate time (checkUprobeParams) and before load (the requirements' uprobearg … ptr — format 18).

// maxUserBuf is the upper bound of N for the [N]byte destination of user.read (bpf-mlir's 1..8192).
const maxUserBuf = 8192

// argTaken reports how argument n of p is already read ("" when it is not — for the "one argument has one type" errors).
func (p *Program) argTaken(n int) (string, token.Pos) {
	if t, ok := p.Params[n]; ok {
		return goIntName(t), p.paramPos[n]
	}
	if pos, ok := p.StrParams[n]; ok {
		return "a user string", pos
	}
	if pos, ok := p.StrArrParams[n]; ok {
		return "a user string array", pos
	}
	if pos, ok := p.PtrParams[n]; ok {
		return "a pointer", pos
	}
	if pos, ok := p.BufParams[n]; ok {
		return "a user buffer", pos
	}
	return "", token.NoPos
}

// uprobeCall checks the shared shape of UprobeBuf / UprobeArg[uintptr] (a uprobe program, the context parameter, a constant argument number) and
// returns n. what is the reading ("a pointer" / "a user buffer") recorded in the program's params.
func (l *lowerer) uprobeCall(call *ast.CallExpr, fn, what string) (int, bool) {
	if l.calleeAttach(call.Pos(), fn) { // a callee that takes the context
		return 0, false
	}
	if l.progKind == nil || l.progKind.Kind != "uprobe" || l.prog == nil {
		// uprobe_multi is out of scope — integer arguments, return values and numbers only (limits).
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be used in a uprobe program (func f(ctx *bpf.UprobeContext) with //gobpf:uprobe) — not in a uprobe_multi program, which reads integer arguments only", fn)
		return 0, false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return 0, false
	}
	n, ok := l.argNumber(call.Args[1], fn)
	if !ok {
		return 0, false
	}
	p := l.prog
	if prev, apos := p.argTaken(n); prev != "" && prev != what {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the uprobe program %s is read as %s at %s and as %s here — one argument has one type (schema params)", n, p.Symbol, prev, posString(l.a.position(apos)), what)
		return 0, false
	}
	params := &p.PtrParams
	if what == "a user buffer" {
		params = &p.BufParams
	}
	if *params == nil {
		*params = map[int]token.Pos{}
	}
	if _, seen := (*params)[n]; !seen {
		(*params)[n] = call.Pos()
	}
	return n, true
}

// uprobePtrConv lowers `uint64(bpf.UprobeArg[uintptr](ctx, n))` (int64 too) of a uprobe program to `ebpf.uprobe.arg %ctx n : … -> i64` and sets the
// schema's params to `{"kind":"ptr"}` (kprobePtrConv's uprobe form — the value is never dereferenced).
func (l *lowerer) uprobePtrConv(e, call *ast.CallExpr) (value, bool, bool) {
	defer l.at(call.Pos())()
	const fn = "bpf.UprobeArg[uintptr]"
	to, isInt := intTypeOf(l.a.info.Types[e].Type)
	if !isInt || to.Bits != 64 {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "%s is the raw 8-byte pointer value — convert it to uint64 or int64 (`uint64(%s(ctx, n))`), got %s", fn, fn, l.a.info.Types[e].Type)
		return value{}, false, true
	}
	n, ok := l.uprobeCall(call, fn, "a pointer")
	if !ok {
		return value{}, false, true
	}
	r := l.val()
	l.emit("%s = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> i64", r, n)
	return value{r, vtypeOf(to)}, true, true
}

// userBufArg lowers the second argument of OutputBuf, `bpf.UprobeBuf(ctx, n)` written in place, to `ebpf.uprobe.arg %ctx n : … -> !ebpf.user_buf`
// (schema `{"kind":"user_buf"}`).
func (l *lowerer) userBufArg(e ast.Expr, m *BpfMap) (string, bool) {
	call, isCall := ast.Unparen(e).(*ast.CallExpr)
	if !isCall || l.callOp(call) != "uprobe_buf" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "the second argument of %s.OutputBuf must be a user buffer written in place: bpf.UprobeBuf(ctx, n)", m.Symbol)
		return "", false
	}
	defer l.at(call.Pos())()
	n, ok := l.uprobeCall(call, "bpf.UprobeBuf", "a user buffer")
	if !ok {
		return "", false
	}
	r := l.val()
	l.emit("%s = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> !ebpf.user_buf", r, n)
	return r, true
}

// isOutputBuf reports whether the call is RingBuf.OutputBuf.
func (l *lowerer) isOutputBuf(e ast.Expr) (*ast.CallExpr, *BpfMap, bool) {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, nil, false
	}
	m, en, _, known := l.mapMethod(call)
	if m == nil || !known || en.op != "output_buf" {
		return call, m, false
	}
	return call, m, true
}

// userBufTagged is the record's exactly one field tagged `gobpf:"<tag>"`, checked by shape (what names the expected type in the error).
func (l *lowerer) userBufTagged(m *BpfMap, at token.Pos, tag, what string, shape func(FieldABI) bool) (FieldABI, bool) {
	st, _ := m.Value.GoType.Underlying().(*types.Struct)
	var found []FieldABI
	for i := 0; st != nil && i < st.NumFields(); i++ {
		if reflect.StructTag(st.Tag(i)).Get("gobpf") != tag {
			continue
		}
		f, ok := m.Value.Record.fieldByGoName(st.Field(i).Name())
		if !ok || !shape(f) {
			l.fail(Rejected, GB016SharedABIShape, at, "the `gobpf:\"%s\"` field %s of %s must be %s", tag, st.Field(i).Name(), m.Value.Record.Symbol, what)
			return FieldABI{}, false
		}
		found = append(found, f)
	}
	if len(found) != 1 {
		l.fail(Rejected, GB016SharedABIShape, at, "%s.OutputBuf needs exactly one field tagged `gobpf:\"%s\"` (%s) in the event record %s, found %d", m.Symbol, tag, what, m.Value.Record.Symbol, len(found))
		return FieldABI{}, false
	}
	return found[0], true
}

// outputBufAssign lowers `st, cnt, ok := R.OutputBuf(v, bpf.UprobeBuf(ctx, n), len)` (any may be `_` — OutputBuf as a statement is mapCall's GB017).
//
//	%b = ebpf.uprobe.arg %ctx n -> !ebpf.user_buf
//	%res = ringbuf.reserve "R"
//	%r:3 = ringbuf.if_reserved %res -> i64, i32, i8 present(%p) { record.make; store_record; %st, %cnt = user.read %p "<field>", %b, %len;
//	                                                  store_field status, %st; store_field len, %cnt; submit; yield %st, %cnt, 1 }
//	                                                  absent { yield 0, 0, 0 }
func (l *lowerer) outputBufAssign(s *ast.AssignStmt, call *ast.CallExpr, m *BpfMap) {
	defer l.at(call.Pos())()
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
		return
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.OutputBuf cannot be inside a loop (bpf-mlir does not allow ring buffer ops in a loop body)", m.Symbol)
		return
	}
	field, ok := l.userBufTagged(m, call.Pos(), "userbuf", fmt.Sprintf("a byte array of 1..%d ([N]byte / [N]int8 — user.read writes the buffer there)", maxUserBuf), func(f FieldABI) bool {
		return f.Type.Kind == ABIArray && f.Type.Array.Elem.Int != nil && f.Type.Array.Elem.Int.Bits == 8 && f.Type.Array.Count >= 1 && f.Type.Array.Count <= maxUserBuf
	})
	if !ok {
		return
	}
	status, ok := l.userBufTagged(m, call.Pos(), "userbuf_status", "int64 (OutputBuf writes the raw probe_read_user status there — the kernel zero-fills the field when the read fails)", func(f FieldABI) bool {
		return f.Type.Kind == ABIInt && f.Type.Int.Bits == 64 && f.Type.Int.Signed
	})
	if !ok {
		return
	}
	length, ok := l.userBufTagged(m, call.Pos(), "userbuf_len", "int32 (OutputBuf writes the clamped requested count there)", func(f FieldABI) bool {
		return f.Type.Kind == ABIInt && f.Type.Int.Bits == 32 && f.Type.Int.Signed
	})
	if !ok {
		return
	}
	if cl, isCL := call.Args[0].(*ast.CompositeLit); isCL {
		for _, el := range cl.Elts {
			kv, isKV := el.(*ast.KeyValueExpr)
			if !isKV {
				continue
			}
			for _, f := range []struct{ tag, name string }{{"userbuf", field.GoName}, {"userbuf_status", status.GoName}, {"userbuf_len", length.GoName}} {
				if kv.Key.(*ast.Ident).Name == f.name {
					l.fail(Rejected, GB016SharedABIShape, kv.Pos(), "the `gobpf:\"%s\"` field %s is written by OutputBuf — leave it out of the event literal", f.tag, f.name)
					return
				}
			}
		}
	}
	b, ok := l.userBufArg(call.Args[1], m)
	if !ok {
		return
	}
	i64, i32, i8 := vtype{bits: 64, signed: true}, vtype{bits: 32, signed: true}, vtype{bits: 8}
	n, ok := l.expr(call.Args[2], &i64)
	if !ok {
		return
	}
	rt := m.Value.mlir()
	res := l.val()
	l.emit("%s = ebpf.ringbuf.reserve %q : !ebpf.maybe_reservation<%s>", res, m.Symbol, rt)
	borrow := l.val()
	present := l.region(func() {
		made, ok2 := l.recordMake(call.Args[0], m.Value)
		if !ok2 {
			ok = false
			return
		}
		defer l.at(call.Pos())()
		l.emit("ebpf.ringbuf.store_record %s, %s : !ebpf.reservation<%s>, %s", borrow, made, rt, rt)
		st, cnt := l.val(), l.val()
		l.emit("%s, %s = ebpf.user.read %s %q, %s, %s : !ebpf.reservation<%s>, !ebpf.user_buf, i64 -> i64, i32", st, cnt, borrow, field.Name, b, n.name, rt)
		l.emit("ebpf.ringbuf.store_field %s[%d], %s : !ebpf.reservation<%s>, i64", borrow, status.Offset, st, rt)
		l.emit("ebpf.ringbuf.store_field %s[%d], %s : !ebpf.reservation<%s>, i32", borrow, length.Offset, cnt, rt)
		l.emit("ebpf.ringbuf.submit %s : !ebpf.reservation<%s>", borrow, rt)
		one := l.constant(constant.MakeInt64(1), i8)
		l.emit("ebpf.yield %s, %s, %s : i64, i32, i8", st, cnt, one.name)
	})
	if !ok {
		return
	}
	absent := l.region(func() {
		defer l.at(call.Pos())()
		z := l.constant(constant.MakeInt64(0), i64)
		z32 := l.constant(constant.MakeInt64(0), i32)
		z8 := l.constant(constant.MakeInt64(0), i8)
		l.emit("ebpf.yield %s, %s, %s : i64, i32, i8", z.name, z32.name, z8.name)
	})
	r := l.val()
	l.b.WriteString(fmt.Sprintf("%s%s:3 = ebpf.ringbuf.if_reserved %s : !ebpf.maybe_reservation<%s> -> i64, i32, i8 present {\n%s^present(%s: !ebpf.reservation<%s>):\n%s%s} absent {\n%s%s}%s\n",
		l.indent, r, res, rt, l.indent, borrow, rt, present, l.indent, absent, l.indent, l.locSuffix(call.Pos())))
	results := []value{{r + "#0", i64}, {r + "#1", i32}, l.fromCarrier(r+"#2", vtype{isBool: true})}
	for i, lhs := range s.Lhs {
		id, _ := lhs.(*ast.Ident)
		if id == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, lhs.Pos(), "assignment target must be a local variable")
			return
		}
		if id.Name == "_" {
			continue
		}
		v := l.localVar(id, s.Tok == token.DEFINE)
		if v == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "assignment target %s must be a local variable", id.Name)
			return
		}
		l.setVar(id, v, results[i])
	}
}
