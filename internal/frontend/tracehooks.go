package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"reflect"
	"regexp"
	"strings"
)

// tracepoint, raw_tp, kretprobe, uretprobe (bpf-mlir's tracepoint / raw_tp / probe.retval):
//
//	//gobpf:tracepoint syscalls/sys_enter_getppid
//	func onTP(ctx *bpf.TracepointContext[GetppidEnter]) {
//		nr := ctx.Event().Nr             → ebpf.tp.field %ctx "__syscall_nr" [8] : !ebpf.ctx<"tracepoint"> -> i32
//	}
//	//gobpf:raw_tp sys_enter
//	func onRaw(ctx *bpf.RawTPContext) {
//		id := bpf.RawTPArg(ctx, 1)        → ebpf.ctx.field %ctx "args"[1] : !ebpf.ctx<"raw_tp"> -> i64
//	}
//	//gobpf:kretprobe bpf_fentry_test1
//	func onRet(ctx *bpf.KretprobeContext[int32]) {
//		r := ctx.Ret()                    → ebpf.probe.retval %ctx : !ebpf.ctx<"kretprobe"> -> i32
//	}
//
// The offsets of a tracepoint event struct are Go's layout (amd64 — the same as C's natural alignment). generate does not read tracefs — the check
// against the real format is the tpfield requirement at load time.

// TPField is a tagged field of a tracepoint event struct (one of the fields of a schema program).
type TPField struct {
	Name   string // the field name in the tracefs format (tag `tp:"…"`)
	GoName string
	Offset int64
	Int    IntType
	Str    bool  // a bpf.UserStr field (a `char *` — the schema's user_str, read only as OutputStr's user string)
	StrArr bool  // a bpf.UserStrArray field (a `char **` — the schema's user_str_array, read only with At)
	Arr    int64 // N of a fixed byte array field [N]byte / [N]int8 (Int is the element — the schema's array, copied only with tp.field.copy); 0 otherwise
}

// tpArrayMax is the upper bound of a tracepoint byte array field (bpf-mlir's tp.field.copy limit).
const tpArrayMax = 64

// isUserStr reports whether t is bpf.UserStr.
func isUserStr(t types.Type) bool { return isBpfNamed(t, "UserStr") }

// isUserStrArray reports whether t is bpf.UserStrArray.
func isUserStrArray(t types.Type) bool { return isBpfNamed(t, "UserStrArray") }

func isBpfNamed(t types.Type, name string) bool {
	n, ok := t.(*types.Named)
	return ok && n.Obj().Pkg() != nil && n.Obj().Pkg().Path() == bpfPkg && n.Obj().Name() == name
}

// tpMaxRecord is the readable limit of a tracepoint record (the kernel's PERF_MAX_TRACE_SIZE — the same as bpf-mlir's tp.field verifier).
const tpMaxRecord = 8192

// tpRawArgMax is the index limit of raw_tp args (bpf_raw_tracepoint_args — the kernel's MAX_BPF_FUNC_ARGS, 12).
const tpRawArgMax = 11

var cIdent = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// tracepointEvent reads E of TracepointContext[E] and puts its tagged fields in p.TPFields (in offset order — Go's struct field order is offset order).
// Anything outside the shape (E not a struct, a tagged field not an integer, offset < 8, beyond 8192, a duplicate name, no tagged field) is GB008.
func (a *analyzer) tracepointEvent(p *Program, ctxType types.Type) {
	fail := func(pos token.Pos, format string, args ...any) {
		at := p.decl.Name.Pos()
		if pos.IsValid() {
			at = pos
		}
		a.report(Rejected, GB008ProgramShape, at, []string{p.Symbol}, "tracepoint program "+p.Symbol+": "+format, args...)
	}
	n, _ := ctxType.(*types.Named)
	if n == nil || n.TypeArgs().Len() != 1 {
		fail(token.NoPos, "the context must be *bpf.TracepointContext[E] with E the event record struct")
		return
	}
	e := n.TypeArgs().At(0)
	en, _ := e.(*types.Named)
	st, _ := e.Underlying().(*types.Struct)
	if en == nil || st == nil {
		fail(token.NoPos, "the event type %s in *bpf.TracepointContext[E] must be a named struct type (the tracefs event record — `_ [8]byte` for the common fields, then the fields to read tagged `tp:\"<name>\"`)", e)
		return
	}
	p.tpEvent = en
	var vars []*types.Var
	for i := 0; i < st.NumFields(); i++ {
		vars = append(vars, st.Field(i))
	}
	offs := amd64Sizes.Offsetsof(vars)
	seen := map[string]bool{}
	ok := true
	for i, f := range vars {
		name, tagged := reflect.StructTag(st.Tag(i)).Lookup("tp")
		if !tagged {
			continue
		}
		if p.tpTagged == nil {
			p.tpTagged = map[string]bool{}
		}
		p.tpTagged[f.Name()] = true // a read of a misshapen field does not report again
		at := f.Pos()
		it, isInt := intTypeOf(f.Type())
		str, strArr := isUserStr(f.Type()), isUserStrArray(f.Type())
		if str || strArr {
			it, isInt = IntType{Bits: 64}, true // the 8-byte pointer (the width of the bounds check below)
		}
		var n int64
		if arr, isArr := f.Type().Underlying().(*types.Array); isArr {
			et, isElem := intTypeOf(arr.Elem())
			if !isElem || et.Bits != 8 || isBoolish(arr.Elem()) || arr.Len() < 1 || arr.Len() > tpArrayMax {
				fail(at, "the tagged array field %s.%s has type %s — a tracepoint array field is a one-dimensional [N]byte or [N]int8 with N 1..%d (copied whole with tp.field.copy)", en.Obj().Name(), f.Name(), f.Type(), tpArrayMax)
				ok = false
				continue
			}
			if strings.HasPrefix(p.Attach, "syscalls/") {
				fail(at, "the tagged array field %s.%s is in a syscalls event — the BPF context of syscalls tracepoints has no inline arrays (only the syscall number and the 8-byte arguments)", en.Obj().Name(), f.Name())
				ok = false
				continue
			}
			it, isInt, n = et, true, arr.Len()
		}
		if !isInt || (!str && !strArr && n == 0 && isBoolish(f.Type())) {
			fail(at, "the tagged field %s.%s has type %s — a tracepoint field read is an 8 / 16 / 32 / 64-bit integer, a [N]byte / [N]int8 array (copied into a record field), a bpf.UserStr (a `char *` user string) or a bpf.UserStrArray (a `char **` array of user strings) (structs and __data_loc fields are not readable in this subset)", en.Obj().Name(), f.Name(), f.Type())
			ok = false
			continue
		}
		if !cIdent.MatchString(name) {
			fail(at, "the tag tp:%q of %s.%s is not a C identifier (the field name in the tracefs format)", name, en.Obj().Name(), f.Name())
			ok = false
			continue
		}
		if seen[name] {
			fail(at, "the tracefs field %q is tagged twice in %s (at %s) — one field, one tag", name, en.Obj().Name(), f.Name())
			ok = false
			continue
		}
		seen[name] = true
		w := int64(it.Bits / 8)
		if n > 0 {
			w = n
		}
		if offs[i] < 8 {
			fail(at, "the tagged field %s.%s is at offset %d — the first 8 bytes of a tracepoint record are the common fields, which BPF cannot read (start the struct with `_ [8]byte`)", en.Obj().Name(), f.Name(), offs[i])
			ok = false
			continue
		}
		if offs[i]+w > tpMaxRecord {
			fail(at, "the tagged field %s.%s ends at byte %d, past the %d-byte limit of a tracepoint record (PERF_MAX_TRACE_SIZE)", en.Obj().Name(), f.Name(), offs[i]+w, tpMaxRecord)
			ok = false
			continue
		}
		p.TPFields = append(p.TPFields, TPField{Name: name, GoName: f.Name(), Offset: offs[i], Int: it, Str: str, StrArr: strArr, Arr: n})
	}
	if ok && len(p.TPFields) == 0 {
		fail(token.NoPos, "the event type %s has no field tagged `tp:\"<name>\"` — tag the fields the program reads (their offsets are checked against the tracefs format at load)", en.Obj().Name())
	}
}

// isBoolish reports whether t is bool (or a named bool).
func isBoolish(t types.Type) bool {
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Kind() == types.Bool
}

// tpEventCall reports whether e is `ctx.Event()` of a tracepoint program (ctx is the program's context parameter).
func (l *lowerer) tpEventCall(e ast.Expr) bool {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	return ok && l.callOp(call) == "tp_event"
}

// tpEventField lowers `ctx.Event().F` to `ebpf.tp.field %ctx "<name>" [<off>]` (handled is false for other shapes).
func (l *lowerer) tpEventField(e ast.Expr) (value, bool, bool) {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || !l.tpEventCall(sel.X) {
		return value{}, false, false
	}
	call := ast.Unparen(sel.X).(*ast.CallExpr)
	defer l.at(sel.Pos())()
	if !l.tpEventPlace(call) {
		return value{}, false, true
	}
	for _, f := range l.prog.TPFields {
		if f.GoName == sel.Sel.Name {
			if f.Str {
				l.fail(Rejected, GB008ProgramShape, sel.Pos(), "%s.%s is a bpf.UserStr (a user string pointer) — it may only be written in place as the second argument of R.OutputStr / R.OutputStrOrDiscard (a user string is not a value)", l.prog.tpEvent.Obj().Name(), f.GoName)
				return value{}, false, true
			}
			if f.StrArr {
				l.fail(Rejected, GB008ProgramShape, sel.Pos(), "%s.%s is a bpf.UserStrArray (an array of user string pointers) — it may only be At's receiver or bound once with `a := ctx.Event().%s` (an array is not a value)", l.prog.tpEvent.Obj().Name(), f.GoName, f.GoName)
				return value{}, false, true
			}
			if f.Arr > 0 {
				l.fail(Rejected, GB008ProgramShape, sel.Pos(), "%s.%s is a %d-byte array — it can only be copied whole into a field of the same type of a checked record (`q.F = ctx.Event().%s` — q a checked map borrow or a reservation: tp.field.copy); its elements cannot be read", l.prog.tpEvent.Obj().Name(), f.GoName, f.Arr, f.GoName)
				return value{}, false, true
			}
			r := l.val()
			t := vtypeOf(f.Int)
			l.emit("%s = ebpf.tp.field %%ctx %q [%d] : !ebpf.ctx<\"tracepoint\"> -> %s", r, f.Name, f.Offset, t.mlir())
			return value{r, t}, true, true
		}
	}
	if l.prog.tpEvent != nil && !l.prog.tpTagged[sel.Sel.Name] {
		l.fail(Rejected, GB008ProgramShape, sel.Sel.Pos(), "%s.%s has no `tp:\"<name>\"` tag — only the tagged fields of the event record are readable (each read is checked against the tracefs format at load)", l.prog.tpEvent.Obj().Name(), sel.Sel.Name)
	} else {
		l.failed = true // the error in E is already reported
	}
	return value{}, false, true
}

// tpEventPlace reports whether ctx.Event() is called on the program's context in the body of a tracepoint program (otherwise it reports and returns false).
func (l *lowerer) tpEventPlace(call *ast.CallExpr) bool {
	fun := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if l.progKind == nil || l.progKind.Kind != "tracepoint" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.Event() may only be used in the body of a tracepoint program (bpf-mlir reads tracepoint fields in the program's entry only)")
		return false
	}
	if id, ok := ast.Unparen(fun.X).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "ctx.Event() must be called on the program's context parameter")
		return false
	}
	return true
}

// rawTPArg lowers `bpf.RawTPArg(ctx, i)` of a raw_tp program to `ebpf.ctx.field %ctx "args"[i] : !ebpf.ctx<"raw_tp"> -> i64`.
func (l *lowerer) rawTPArg(call *ast.CallExpr) (value, bool, bool) {
	if l.callOp(call) != "rawtp_arg" {
		return value{}, false, false
	}
	defer l.at(call.Pos())()
	if l.progKind == nil || l.progKind.Kind != "raw_tp" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "bpf.RawTPArg may only be called in the body of a raw_tp program (func f(ctx *bpf.RawTPContext) with //gobpf:raw_tp)")
		return value{}, false, true
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of bpf.RawTPArg must be the program's context parameter")
		return value{}, false, true
	}
	tv := l.a.info.Types[call.Args[1]]
	i, exact := int64(-1), false
	if tv.Value != nil {
		i, exact = constant.Int64Val(constant.ToInt(tv.Value))
	}
	if tv.Value == nil || !exact || i < 0 || i > tpRawArgMax {
		l.fail(Rejected, GB008ProgramShape, call.Args[1].Pos(), "the argument index of bpf.RawTPArg must be a constant 0..%d (bpf_raw_tracepoint_args — the kernel rejects an index past the tracepoint's arguments at load)", tpRawArgMax)
		return value{}, false, true
	}
	r := l.val()
	l.emit("%s = ebpf.ctx.field %%ctx \"args\"[%d] : !ebpf.ctx<\"raw_tp\"> -> i64", r, i)
	return value{r, vtype{bits: 64}}, true, true
}
