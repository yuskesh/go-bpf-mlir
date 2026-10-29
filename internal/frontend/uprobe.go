package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/internal/uprobeabi"
)

// uprobe (bpf-mlir's uprobe, uprobe.arg, user.read_str).
//
//	//gobpf:uprobe fixture/cfix sum_args          ← path relative to the package directory, used only at generate time (sha256, symbol, calling convention, DWARF)
//	func onSum(ctx *bpf.UprobeContext) {
//		a := bpf.UprobeArg[int64](ctx, 1)        → ebpf.uprobe.arg %ctx 1 : !ebpf.ctx<"uprobe"> -> i64
//		st, ok := Ev.OutputStr(E{…}, bpf.UprobeStr(ctx, 2))
//	}
//
// The path goes into neither the schema, the ELF nor the generated file (only the hash — the run-time path and PID are loader inputs). The calling
// convention verdict uses the same table as bpf-mlir (the CU's DW_AT_language).

// uprobeDirectiveInfo is the directive of a uprobe program.
type uprobeDirectiveInfo struct {
	path string
	pos  token.Pos
}

// uprobeDirective reads the two words of `//gobpf:uprobe <path> <symbol>` (from tracingTarget — word count, symbol shape). kind is uprobe or uretprobe.
func (a *analyzer) uprobeDirective(fd *ast.FuncDecl, at token.Pos, kind string, fields []string) (string, int, bool) {
	if isMultiKind(kind) {
		// `//gobpf:uprobe_multi <path> s1 s2 …` — a path and a list of symbols (one or more, no duplicates, no globs).
		if len(fields) == 0 {
			a.multiList(fd, at, kind, nil, "symbol")
			return "", 0, false
		}
		if !a.multiList(fd, at, kind, fields[1:], "symbol") {
			return "", 0, false
		}
		a.uprobeDecl[fd] = uprobeDirectiveInfo{path: fields[0], pos: at}
		return strings.Join(fields[1:], " "), 0, true
	}
	if len(fields) != 2 || !kernelFuncName.MatchString(fields[1]) {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s takes the binary's path (relative to the package directory — used only at generate time) and the symbol: `//gobpf:%s <path> <symbol>`, got %q", kind, kind, strings.Join(fields, " "))
		return "", 0, false
	}
	a.uprobeDecl[fd] = uprobeDirectiveInfo{path: fields[0], pos: at}
	return fields[1], 0, true
}

// checkUprobeBinaries checks the target binary of each uprobe program at generate time (early, with a named error — in production the same check runs
// in the pre-load gate and the gobpf runtime). The path is only relative to the package directory.
func (a *analyzer) checkUprobeBinaries() {
	for _, p := range a.programs {
		if !isUprobeKind(p.ProgramType) {
			continue
		}
		d, ok := a.uprobeDecl[p.decl]
		if !ok {
			continue // the directive error is already reported
		}
		p.Binary, p.dirPos = d.path, d.pos
		fail := func(format string, args ...any) {
			a.report(Rejected, GB008ProgramShape, d.pos, []string{p.Symbol}, p.ProgramType+" program %s: "+format, append([]any{p.Symbol}, args...)...)
		}
		if filepath.IsAbs(d.path) || strings.HasPrefix(filepath.Clean(d.path), "..") {
			fail("the binary path %q must be relative to the package directory and inside it (it is hashed at generate time; the run-time path is gobpf.Load's WithUprobeTarget)", d.path)
			continue
		}
		f, err := os.Open(filepath.Join(a.dir, d.path))
		if err != nil {
			fail("cannot open the target binary %s: %v", d.path, err)
			continue
		}
		// uprobe_multi checks each symbol of the list (one binary — the same sha256).
		params := map[string][]string{}
		sha := ""
		for _, sym := range strings.Fields(p.Attach) {
			info, err := uprobeabi.Inspect(f, sym)
			if err != nil {
				fail("%s: %v", d.path, err)
				sha = ""
				break
			}
			sha, params[sym] = info.SHA256, info.Params
		}
		f.Close()
		if sha != "" {
			p.BinarySHA256, p.uprobeParams = sha, params
		}
	}
}

// checkUprobeParams checks the UprobeArg types and UprobeStr arguments collected by lowering against the target's DWARF argument types (at generate
// time — the pre-load gate does the same check).
func (a *analyzer) checkUprobeParams() {
	for _, p := range a.programs {
		if (p.ProgramType != "uprobe" && p.ProgramType != "uprobe_multi") || p.BinarySHA256 == "" {
			continue
		}
		// uprobe_multi uses the same types for every symbol in the list (per-symbol types are out of scope). Only the first mismatch is reported.
		check := func(n int, want string, pos token.Pos) {
			for _, sym := range strings.Fields(p.Attach) {
				ps := p.uprobeParams[sym]
				if n > len(ps) {
					a.report(Rejected, GB008ProgramShape, pos, []string{p.Symbol}, "%s program %s reads argument %d of %s, which takes %d arguments in the binary's DWARF", p.ProgramType, p.Symbol, n, sym, len(ps))
					return
				}
				if got := ps[n-1]; got != want {
					a.report(Rejected, GB008ProgramShape, pos, []string{p.Symbol}, "%s program %s reads argument %d of %s as %s, but it is %s in the binary's DWARF", p.ProgramType, p.Symbol, n, sym, want, orUnreadable(got))
					return
				}
			}
		}
		for _, n := range p.paramOrder() {
			check(n, intSpelling(p.Params[n]), p.paramPos[n])
		}
		for n, pos := range p.StrParams {
			check(n, "strptr", pos)
		}
	}
}

func orUnreadable(s string) string {
	if s == "" {
		return "a type this check cannot read"
	}
	return s
}

// intSpelling is the requirements spelling of an integer type (i8 to u64).
func intSpelling(t IntType) string {
	if t.Signed {
		return fmt.Sprintf("i%d", t.Bits)
	}
	return fmt.Sprintf("u%d", t.Bits)
}

// uprobeStrCall reports whether the call is bpf.UprobeStr.
func (l *lowerer) uprobeStrCall(e ast.Expr) (*ast.CallExpr, bool) {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, false
	}
	var obj types.Object
	switch f := ast.Unparen(call.Fun).(type) {
	case *ast.SelectorExpr:
		obj = l.a.info.Uses[f.Sel]
	case *ast.Ident:
		obj = l.a.info.Uses[f]
	}
	if obj == nil || !inAPIPackage(obj) {
		return nil, false
	}
	en, known := lookupAPI(obj)
	return call, known && en.op == "uprobe_str"
}

// userStrArg lowers the second argument of OutputStr, `bpf.UprobeStr(ctx, n)`, to `ebpf.uprobe.arg %ctx n -> !ebpf.user_str`.
func (l *lowerer) userStrArg(e ast.Expr, m *BpfMap) (string, bool) {
	call, ok := l.uprobeStrCall(e)
	if !ok {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "the second argument of %s.OutputStr / OutputStrOrDiscard must be bpf.UprobeStr(ctx, n) written in place", m.Symbol)
		return "", false
	}
	if l.calleeAttach(call.Pos(), "bpf.UprobeStr") { // a callee that takes the context
		return "", false
	}
	if l.progKind == nil || l.progKind.Kind != "uprobe" || l.prog == nil {
		// uprobe_multi is out of scope — integer arguments, return values and numbers only (no demand — limits).
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "bpf.UprobeStr may only be used in a uprobe program (func f(ctx *bpf.UprobeContext) with //gobpf:uprobe) — not in a uprobe_multi program, which reads integer arguments only")
		return "", false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of bpf.UprobeStr must be the program's context parameter")
		return "", false
	}
	n, ok := l.argNumber(call.Args[1], "bpf.UprobeStr")
	if !ok {
		return "", false
	}
	p := l.prog
	if _, taken := p.Params[n]; taken {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the uprobe program %s is read as an integer at %s and as a user string here — one argument has one type", n, p.Symbol, posString(l.a.position(p.paramPos[n])))
		return "", false
	}
	if p.StrParams == nil {
		p.StrParams = map[int]token.Pos{}
	}
	if _, seen := p.StrParams[n]; !seen {
		p.StrParams[n] = call.Pos()
	}
	r := l.val()
	l.emit("%s = ebpf.uprobe.arg %%ctx %d : !ebpf.ctx<\"uprobe\"> -> !ebpf.user_str", r, n)
	return r, true
}

// argNumber is the argument number of KprobeArg / UprobeArg / UprobeStr (a constant from 1 to 6).
func (l *lowerer) argNumber(e ast.Expr, what string) (int, bool) {
	tv := l.a.info.Types[e]
	n, exact := int64(0), false
	if tv.Value != nil {
		n, exact = constant.Int64Val(constant.ToInt(tv.Value))
	}
	if tv.Value == nil || !exact || n < 1 || n > kprobeMaxArg {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "the argument number of %s must be a constant 1..%d (x86_64 passes the first %d arguments in registers; stack arguments are not readable)", what, kprobeMaxArg, kprobeMaxArg)
		return 0, false
	}
	return int(n), true
}

// strOut is the variant of the RingBuf method that reads a string into the event (OutputStr, OutputStrOrDiscard — a user string, OutputKernelStr — a kernel
// char * string).
type strOut struct {
	method  string
	discard bool
	kernel  bool
}

// tag is the tag of the string field (`gobpf:"<tag>"` — the status is `<tag>_status`).
func (o strOut) tag() string {
	if o.kernel {
		return "kernelstr"
	}
	return "userstr"
}

// op is the bpf-mlir op that reads the string.
func (o strOut) op() string {
	if o.kernel {
		return "kernel.read_str"
	}
	return "user.read_str"
}

// maxKernelStr is the upper bound of N for the [N]byte destination of kernel.read_str (ebpf-verify-records accepts 1 to 64 elements).
const maxKernelStr = 64

// userStrField is the schema name of the record's exactly one byte array field tagged `gobpf:"userstr"` (`gobpf:"kernelstr"` for OutputKernelStr)
// (the write destination).
func (l *lowerer) userStrField(m *BpfMap, at token.Pos, o strOut) (FieldABI, bool) {
	st, _ := m.Value.GoType.Underlying().(*types.Struct)
	var found []FieldABI
	for i := 0; st != nil && i < st.NumFields(); i++ {
		if reflect.StructTag(st.Tag(i)).Get("gobpf") != o.tag() {
			continue
		}
		f, ok := m.Value.Record.fieldByGoName(st.Field(i).Name())
		if !ok || f.Type.Kind != ABIArray || f.Type.Array.Elem.Int == nil || f.Type.Array.Elem.Int.Bits != 8 {
			l.fail(Rejected, GB016SharedABIShape, at, "the `gobpf:\"%s\"` field %s of %s must be a byte array ([N]uint8 / [N]byte — %s writes the string there)", o.tag(), st.Field(i).Name(), m.Value.Record.Symbol, o.op())
			return FieldABI{}, false
		}
		if o.kernel && (f.Type.Array.Count < 1 || f.Type.Array.Count > maxKernelStr) {
			l.fail(Rejected, GB016SharedABIShape, at, "the `gobpf:\"kernelstr\"` field %s of %s has %d bytes — kernel.read_str writes into a byte array of 1..%d", st.Field(i).Name(), m.Value.Record.Symbol, f.Type.Array.Count, maxKernelStr)
			return FieldABI{}, false
		}
		found = append(found, f)
	}
	if len(found) != 1 {
		l.fail(Rejected, GB016SharedABIShape, at, "%s.%s needs exactly one field tagged `gobpf:\"%s\"` in the event record %s, found %d", m.Symbol, o.method, o.tag(), m.Value.Record.Symbol, len(found))
		return FieldABI{}, false
	}
	return found[0], true
}

// userStrStatusField is the record's exactly one int64 field tagged `gobpf:"userstr_status"` (where OutputStr writes the read_str status).
// Required: on a read_str failure the kernel fills the string field with 0, so without the status in the event a reader sees a failure and an empty
// string as the same bytes (OutputStr also submits events whose read failed). When optional (OutputStrOrDiscard: failed events are discarded,
// so no status is needed) zero fields are accepted (present = false), and if present it is one int64.
func (l *lowerer) userStrStatusField(m *BpfMap, at token.Pos, o strOut) (f FieldABI, present, ok bool) {
	optional := o.discard
	statusTag := o.tag() + "_status"
	st, _ := m.Value.GoType.Underlying().(*types.Struct)
	var found []FieldABI
	for i := 0; st != nil && i < st.NumFields(); i++ {
		if reflect.StructTag(st.Tag(i)).Get("gobpf") != statusTag {
			continue
		}
		f, fok := m.Value.Record.fieldByGoName(st.Field(i).Name())
		if !fok || f.Type.Kind != ABIInt || f.Type.Int.Bits != 64 || !f.Type.Int.Signed {
			what := "OutputStr"
			if o.kernel {
				what = o.method
			}
			l.fail(Rejected, GB016SharedABIShape, at, "the `gobpf:\"%s\"` field %s of %s must be int64 (%s writes the raw status of %s there)", statusTag, st.Field(i).Name(), m.Value.Record.Symbol, what, o.op())
			return FieldABI{}, false, false
		}
		found = append(found, f)
	}
	if optional && len(found) == 0 {
		return FieldABI{}, false, true
	}
	if optional && len(found) > 1 {
		l.fail(Rejected, GB016SharedABIShape, at, "%s.OutputStrOrDiscard takes at most one int64 field tagged `gobpf:\"userstr_status\"` in the event record %s, found %d", m.Symbol, m.Value.Record.Symbol, len(found))
		return FieldABI{}, false, false
	}
	if len(found) != 1 && o.kernel {
		l.fail(Rejected, GB016SharedABIShape, at, "%s.%s needs exactly one int64 field tagged `gobpf:\"kernelstr_status\"` in the event record %s, found %d — the kernel zero-fills the string when the read fails, so without the status in the event a reader cannot tell a failed read from an empty string; add a field `Status int64` with the tag `schema:\"status\" gobpf:\"kernelstr_status\"` and skip events with Status < 0", m.Symbol, o.method, m.Value.Record.Symbol, len(found))
		return FieldABI{}, false, false
	}
	if len(found) != 1 {
		l.fail(Rejected, GB016SharedABIShape, at, "%s.OutputStr needs exactly one int64 field tagged `gobpf:\"userstr_status\"` in the event record %s, found %d — the kernel zero-fills the string when the read fails, so without the status in the event a reader cannot tell a failed read from an empty string; add a field `Status int64` with the tag `schema:\"status\" gobpf:\"userstr_status\"` and skip events with Status < 0 (or use %s.OutputStrOrDiscard, which does not submit failed reads)", m.Symbol, m.Value.Record.Symbol, len(found), m.Symbol)
		return FieldABI{}, false, false
	}
	return found[0], true, true
}

// isOutputStr reports whether the call is RingBuf.OutputStr, RingBuf.OutputStrOrDiscard (discard) or RingBuf.OutputKernelStr
// (kernel).
func (l *lowerer) isOutputStr(e ast.Expr) (*ast.CallExpr, *BpfMap, bool, strOut) {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	if !ok {
		return nil, nil, false, strOut{}
	}
	m, en, _, known := l.mapMethod(call)
	if m == nil || !known {
		return call, m, false, strOut{}
	}
	switch en.op {
	case "output_str":
		return call, m, true, strOut{method: "OutputStr"}
	case "output_str_discard":
		return call, m, true, strOut{method: "OutputStrOrDiscard", discard: true}
	case "output_kernel_str":
		return call, m, true, strOut{method: "OutputKernelStr", kernel: true}
	}
	return call, m, false, strOut{}
}

// kernelStrArg returns the kptr value, local type and field of the second argument of OutputKernelStr, `p.F` (p is a checked kernel pointer,
// F is a bpf.KernelStr field).
func (l *lowerer) kernelStrArg(e ast.Expr, m *BpfMap) (kp kptrVal, field string, ok bool) {
	kp, f, _, handled := l.kptrSel(e)
	if handled && f == nil {
		return kp, "", false // already reported by kptrSel
	}
	if !handled || f.Kind != kfStrPtr {
		l.fail(Rejected, GB027KernelTypeShape, e.Pos(), "the second argument of %s.OutputKernelStr must be a bpf.KernelStr field of a checked kernel pointer written in place (`p.F` — p from bpf.FentryArg / bpf.TPArg / a checked pointer field)", m.Symbol)
		return kp, "", false
	}
	return kp, f.Name, true
}

// outputStrAssign lowers `st, ok := R.OutputStr(v, bpf.UprobeStr(ctx, n))` (either may be `_` — OutputStr as a statement is mapCall's GB017).
//
//	%s = ebpf.uprobe.arg %ctx n -> !ebpf.user_str
//	%res = ringbuf.reserve "R"
//	%r:2 = ringbuf.if_reserved %res -> i64, i8 present(%b) { record.make; store_record; %st = user.read_str %b "<field>", %s;
//	                                            store_field %b[<status offset>], %st; submit; yield %st, 1 }
//	                                            absent { yield 0, 0 }
//
// discard (`st, sent := R.OutputStrOrDiscard(…)` — bpf-mlir's conditional consume inside present): after read_str (after store_field if the status
// field exists) emit `%neg = cmpi slt %st, 0; %sent = ebpf.if %neg -> i8 { discard; yield 0 } else { submit; yield 1 }; yield %st, %sent`.
// The discard condition is only st < 0 (st for an empty string differs by kernel — 1 on 7.1.8, 0 on 6.12 / 6.6 — so an empty string is submitted).
func (l *lowerer) outputStrAssign(s *ast.AssignStmt, call *ast.CallExpr, m *BpfMap, o strOut) {
	defer l.at(call.Pos())()
	method, discard := o.method, o.discard
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
		return
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s.%s cannot be inside a loop (bpf-mlir does not allow ring buffer ops in a loop body)", m.Symbol, method)
		return
	}
	field, ok := l.userStrField(m, call.Pos(), o)
	if !ok {
		return
	}
	status, hasStatus, ok := l.userStrStatusField(m, call.Pos(), o)
	if !ok {
		return
	}
	if cl, isCL := call.Args[0].(*ast.CompositeLit); isCL {
		for _, el := range cl.Elts {
			kv, isKV := el.(*ast.KeyValueExpr)
			if !isKV {
				continue
			}
			switch kv.Key.(*ast.Ident).Name {
			case field.GoName:
				l.fail(Rejected, GB016SharedABIShape, kv.Pos(), "the `gobpf:\"%s\"` field %s is written by %s — leave it out of the event literal", o.tag(), field.GoName, method)
				return
			case status.GoName:
				if hasStatus {
					l.fail(Rejected, GB016SharedABIShape, kv.Pos(), "the `gobpf:\"%s_status\"` field %s is written by %s — leave it out of the event literal", o.tag(), status.GoName, method)
					return
				}
			}
		}
	}
	// read is the one statement inside the reservation's present (user.read_str or kernel.read_str).
	var read func(borrow, rt string) string
	if o.kernel {
		kp, kfield, ok := l.kernelStrArg(call.Args[1], m)
		if !ok {
			return
		}
		read = func(borrow, rt string) string {
			st := l.val()
			l.emit("%s = ebpf.kernel.read_str %s %q, %s %q : !ebpf.reservation<%s>, !ebpf.kptr<%q> -> i64", st, borrow, field.Name, kp.name, kfield, rt, kp.kt.Name)
			return st
		}
	} else {
		sv, ok := l.userStrArg(call.Args[1], m)
		if !ok {
			return
		}
		read = func(borrow, rt string) string {
			st := l.val()
			l.emit("%s = ebpf.user.read_str %s %q, %s : !ebpf.reservation<%s>, !ebpf.user_str -> i64", st, borrow, field.Name, sv, rt)
			return st
		}
	}
	rt := m.Value.mlir()
	res := l.val()
	l.emit("%s = ebpf.ringbuf.reserve %q : !ebpf.maybe_reservation<%s>", res, m.Symbol, rt)
	borrow := l.val()
	i64, i8 := vtype{bits: 64, signed: true}, vtype{bits: 8}
	present := l.region(func() {
		made, ok2 := l.recordMake(call.Args[0], m.Value)
		if !ok2 {
			ok = false
			return
		}
		defer l.at(call.Pos())()
		l.emit("ebpf.ringbuf.store_record %s, %s : !ebpf.reservation<%s>, %s", borrow, made, rt, rt)
		st := read(borrow, rt)
		if hasStatus {
			l.emit("ebpf.ringbuf.store_field %s[%d], %s : !ebpf.reservation<%s>, i64", borrow, status.Offset, st, rt)
		}
		if !discard {
			l.emit("ebpf.ringbuf.submit %s : !ebpf.reservation<%s>", borrow, rt)
			one := l.constant(constant.MakeInt64(1), i8)
			l.emit("ebpf.yield %s, %s : i64, i8", st, one.name)
			return
		}
		z := l.constant(constant.MakeInt64(0), i64)
		neg := l.val()
		l.emit("%s = arith.cmpi slt, %s, %s : i64", neg, st, z.name)
		z8 := l.constant(constant.MakeInt64(0), i8)
		one := l.constant(constant.MakeInt64(1), i8)
		thenT := l.region(func() {
			l.emit("ebpf.ringbuf.discard %s : !ebpf.reservation<%s>", borrow, rt)
			l.emit("ebpf.if.yield %s : i8", z8.name)
		})
		elseT := l.region(func() {
			l.emit("ebpf.ringbuf.submit %s : !ebpf.reservation<%s>", borrow, rt)
			l.emit("ebpf.if.yield %s : i8", one.name)
		})
		sent := l.val()
		l.b.WriteString(fmt.Sprintf("%s%s = ebpf.if %s -> i8 {\n%s%s} else {\n%s%s}%s\n", l.indent, sent, neg, thenT, l.indent, elseT, l.indent, l.locSuffix(call.Pos())))
		l.emit("ebpf.yield %s, %s : i64, i8", st, sent)
	})
	if !ok {
		return
	}
	absent := l.region(func() {
		defer l.at(call.Pos())()
		z := l.constant(constant.MakeInt64(0), i64)
		z8 := l.constant(constant.MakeInt64(0), i8)
		l.emit("ebpf.yield %s, %s : i64, i8", z.name, z8.name)
	})
	r := l.val()
	l.b.WriteString(fmt.Sprintf("%s%s:2 = ebpf.ringbuf.if_reserved %s : !ebpf.maybe_reservation<%s> -> i64, i8 present {\n%s^present(%s: !ebpf.reservation<%s>):\n%s%s} absent {\n%s%s}%s\n",
		l.indent, r, res, rt, l.indent, borrow, rt, present, l.indent, absent, l.indent, l.locSuffix(call.Pos())))
	results := []value{{r + "#0", i64}, l.fromCarrier(r+"#1", vtype{isBool: true})}
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
