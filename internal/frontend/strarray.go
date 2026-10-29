package frontend

// User string arrays (bpf.UserStrArray — argv, a `char **`; bpf-mlir's !ebpf.user_str_array and ebpf.user.str_at):
//
//	argv := ctx.Event().Argv               // or bpf.KsyscallStrArray(ctx, 2), or the source written in place as At's receiver
//	s0, st0, ok0 := argv.At(0)
//	_, _ = Events.OutputStr(Ev{Index: 0, Slot: st0}, s0)
//	if ok0 {
//		s1, st1, ok1 := argv.At(1)          // only here: At(0)'s present is known true
//		…
//	}
//
// The chain is enforced (stricter than bpf-mlir, which leaves it to the caller): At(K) with K > 0 is accepted only inside the then arm of `if ok {` where ok is
// At(K−1)'s present on the same array (the same source — the tracepoint field or the ksyscall argument). An array ends at its first NULL; the slots after it are not
// part of it (after argv's NULL come envp's strings), so reading them would silently report other strings as elements. ok, s and the array variable are never
// reassigned (the chain rests on ok keeping At's value). Not in loops (str_at is not accepted in a loop) or subprograms.

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strconv"
)

// strAtMax is the largest At index (bpf-mlir's user.str_at index attribute 0..19).
const strAtMax = 19

// strArr is a UserStrArray value: the !ebpf.user_str_array SSA name and the identity of its source ("tp:<field>" / "ks:<n>").
type strArr struct{ name, key string }

// strAtFact is "At(k)'s present on the array key".
type strAtFact struct {
	key string
	k   int
}

// isStrAtCall reports whether e is `a.At(i)` of a bpf.UserStrArray.
func (l *lowerer) isStrAtCall(e ast.Expr) (*ast.CallExpr, bool) {
	call, ok := ast.Unparen(e).(*ast.CallExpr)
	return call, ok && l.callOp(call) == "str_at"
}

// strArrPlace reports whether a user string array may be read here (the body of a tracepoint or ksyscall program, outside loops); otherwise it reports.
func (l *lowerer) strArrPlace(pos token.Pos) bool {
	if !l.isProg || l.prog == nil || l.calleeCtx {
		l.fail(Rejected, GB008ProgramShape, pos, "a bpf.UserStrArray may only be read in the body of a tracepoint or ksyscall program — not in a subprogram (bpf-mlir's user.str_at reads a source of the same program)")
		return false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB008ProgramShape, pos, "UserStrArray.At may not be inside a loop (bpf-mlir's user.str_at is not accepted in a loop) — write the elements out with constant indices, each inside `if ok {` of the previous one")
		return false
	}
	return true
}

// strArrSource lowers a UserStrArray: a bound variable, `ctx.Event().F` (F a bpf.UserStrArray field — tracepoint) or `bpf.KsyscallStrArray(ctx, n)` (ksyscall).
func (l *lowerer) strArrSource(e ast.Expr) (strArr, bool) {
	e = ast.Unparen(e)
	if id, ok := e.(*ast.Ident); ok {
		if v, _ := l.a.info.Uses[id].(*types.Var); v != nil {
			if a, bound := l.strArrs[v]; bound {
				return a, true
			}
		}
	}
	if sel, ok := e.(*ast.SelectorExpr); ok && l.tpEventCall(sel.X) {
		defer l.at(sel.Pos())()
		if !l.tpEventPlace(ast.Unparen(sel.X).(*ast.CallExpr)) {
			return strArr{}, false
		}
		for _, f := range l.prog.TPFields {
			if f.GoName != sel.Sel.Name || !f.StrArr { // another field type here is a Go type error (At's receiver is UserStrArray)
				continue
			}
			r := l.val()
			l.emit("%s = ebpf.tp.field %%ctx %q [%d] : !ebpf.ctx<\"tracepoint\"> -> !ebpf.user_str_array", r, f.Name, f.Offset)
			return strArr{r, "tp:" + f.Name}, true
		}
		if l.prog.tpEvent != nil && !l.prog.tpTagged[sel.Sel.Name] {
			l.fail(Rejected, GB008ProgramShape, sel.Sel.Pos(), "%s.%s has no `tp:\"<name>\"` tag — only the tagged fields of the event record are readable (each read is checked against the tracefs format at load)", l.prog.tpEvent.Obj().Name(), sel.Sel.Name)
		} else {
			l.failed = true // the error in E is already reported
		}
		return strArr{}, false
	}
	if call, ok := e.(*ast.CallExpr); ok && l.callOp(call) == "ksyscall_str_array" {
		return l.ksyscallStrArray(call)
	}
	l.fail(Rejected, GB008ProgramShape, e.Pos(), "a bpf.UserStrArray must come from ctx.Event().F (a bpf.UserStrArray field — tracepoint), bpf.KsyscallStrArray(ctx, n) (ksyscall) or a variable bound once to one of them")
	return strArr{}, false
}

// ksyscallStrArray lowers `bpf.KsyscallStrArray(ctx, n)` to `ebpf.ksyscall.arg %ctx n : … -> !ebpf.user_str_array` (the schema's params user_str_array).
func (l *lowerer) ksyscallStrArray(call *ast.CallExpr) (strArr, bool) {
	const fn = "bpf.KsyscallStrArray"
	defer l.at(call.Pos())()
	if l.progKind == nil || l.progKind.Kind != "ksyscall" {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be used in a ksyscall program (func f(ctx *bpf.KsyscallContext) with //gobpf:ksyscall <syscall>)", fn)
		return strArr{}, false
	}
	if id, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return strArr{}, false
	}
	n, ok := l.argNumber(call.Args[1], fn)
	if !ok {
		return strArr{}, false
	}
	p := l.prog
	if _, taken := p.Params[n]; taken {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the ksyscall program %s is read as an integer at %s and as a user string array here — one argument has one type", n, p.Symbol, posString(l.a.position(p.paramPos[n])))
		return strArr{}, false
	}
	if spos, isStr := p.StrParams[n]; isStr {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the ksyscall program %s is read as a user string at %s and as a user string array here — one argument has one type", n, p.Symbol, posString(l.a.position(spos)))
		return strArr{}, false
	}
	if p.StrArrParams == nil {
		p.StrArrParams = map[int]token.Pos{}
	}
	if _, seen := p.StrArrParams[n]; !seen {
		p.StrArrParams[n] = call.Pos()
	}
	r := l.val()
	l.emit("%s = ebpf.ksyscall.arg %%ctx %d : !ebpf.ctx<\"ksyscall\"> -> !ebpf.user_str_array", r, n)
	return strArr{r, "ks:" + strconv.Itoa(n)}, true
}

// strArrBind lowers `a := <source>` (a bpf.UserStrArray bound once to a new local variable).
func (l *lowerer) strArrBind(s *ast.AssignStmt) {
	id, _ := s.Lhs[0].(*ast.Ident)
	var v *types.Var
	if id != nil && s.Tok == token.DEFINE {
		v, _ = l.a.info.Defs[id].(*types.Var)
	}
	if v == nil {
		l.fail(Rejected, GB008ProgramShape, s.Lhs[0].Pos(), "a bpf.UserStrArray may only be bound once to a new variable (`a := ctx.Event().F` / `a := bpf.KsyscallStrArray(ctx, n)`) — not assigned again")
		return
	}
	if _, isVar := ast.Unparen(s.Rhs[0]).(*ast.Ident); isVar {
		l.fail(Rejected, GB008ProgramShape, s.Rhs[0].Pos(), "bind a bpf.UserStrArray from its source (ctx.Event().F or bpf.KsyscallStrArray(ctx, n)), not from another variable")
		return
	}
	if !l.strArrPlace(s.Pos()) {
		return
	}
	a, ok := l.strArrSource(s.Rhs[0])
	if !ok {
		return
	}
	if l.strArrs == nil {
		l.strArrs = map[*types.Var]strArr{}
	}
	l.strArrs[v] = a
}

// strAtAssign lowers `s, st, ok := a.At(K)` to `%s, %st, %ok = ebpf.user.str_at %a [K] : !ebpf.user_str_array -> (!ebpf.user_str, i64, i1)`.
func (l *lowerer) strAtAssign(s *ast.AssignStmt, call *ast.CallExpr) {
	defer l.at(call.Pos())()
	if s.Tok != token.DEFINE {
		l.fail(Rejected, GB008ProgramShape, s.Pos(), "UserStrArray.At is accepted only as `s, st, ok := a.At(i)` declaring new variables (they are never reassigned)")
		return
	}
	for _, lhs := range s.Lhs {
		if id := lhs.(*ast.Ident); id.Name != "_" && l.a.info.Defs[id] == nil {
			l.fail(Rejected, GB008ProgramShape, id.Pos(), "%s is assigned again by UserStrArray.At — `s, st, ok := a.At(i)` declares new variables (they are never reassigned)", id.Name)
			return
		}
	}
	if !l.strArrPlace(call.Pos()) {
		return
	}
	tv := l.a.info.Types[call.Args[0]]
	k, exact := int64(-1), false
	if tv.Value != nil {
		k, exact = constant.Int64Val(constant.ToInt(tv.Value))
	}
	if tv.Value == nil || !exact || k < 0 || k > strAtMax {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the index of UserStrArray.At must be a constant 0..%d (bpf-mlir's user.str_at reads one fixed slot; at most the first %d elements are readable)", strAtMax, strAtMax+1)
		return
	}
	a, ok := l.strArrSource(ast.Unparen(call.Fun).(*ast.SelectorExpr).X)
	if !ok {
		return
	}
	if k > 0 && !l.strAtProven(strAtFact{a.key, int(k) - 1}) {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "UserStrArray.At(%d) is read where At(%d)'s present on the same array is not known true — write it inside `if ok {` of `s, st, ok := a.At(%d)` (an array ends at its first NULL; the slots after it are not part of it — after argv come envp's strings)", k, k-1, k-1)
		return
	}
	sv, st, pv := l.val(), l.val(), l.val()
	l.emit("%s, %s, %s = ebpf.user.str_at %s [%d] : !ebpf.user_str_array -> (!ebpf.user_str, i64, i1)", sv, st, pv, a.name, k)
	bind := func(i int) *types.Var {
		v, _ := l.a.info.Defs[s.Lhs[i].(*ast.Ident)].(*types.Var)
		return v
	}
	if v := bind(0); v != nil {
		if l.strVars == nil {
			l.strVars = map[*types.Var]string{}
		}
		l.strVars[v] = sv
	}
	if v := bind(1); v != nil {
		l.env[v] = value{st, vtype{bits: 64, signed: true}}
	}
	if v := bind(2); v != nil {
		l.env[v] = value{pv, vtype{isBool: true}}
		if l.okVars == nil {
			l.okVars = map[*types.Var]strAtFact{}
		}
		l.okVars[v] = strAtFact{a.key, int(k)}
	}
}

// strAtProven reports whether f holds here (an enclosing then arm of `if ok {`).
func (l *lowerer) strAtProven(f strAtFact) bool {
	for _, g := range l.okProven {
		if g == f {
			return true
		}
	}
	return false
}

// strAtCond is the fact of an if condition that is exactly an At present variable (nil otherwise).
func (l *lowerer) strAtCond(cond ast.Expr) *strAtFact {
	id, ok := ast.Unparen(cond).(*ast.Ident)
	if !ok {
		return nil
	}
	v, _ := l.a.info.Uses[id].(*types.Var)
	if f, isOK := l.okVars[v]; isOK {
		return &f
	}
	return nil
}

// strAtReassigned reports (and fails) when v is an At result or a bound UserStrArray (never reassigned — the chain rests on ok keeping At's value).
func (l *lowerer) strAtReassigned(id *ast.Ident, v *types.Var) bool {
	_, isOK := l.okVars[v]
	_, isS := l.strVars[v]
	_, isArr := l.strArrs[v]
	if isOK || isS || isArr {
		l.fail(Rejected, GB008ProgramShape, id.Pos(), "%s comes from UserStrArray.At or binds a bpf.UserStrArray and must not be reassigned (the At chain rests on it)", id.Name)
		return true
	}
	return false
}
