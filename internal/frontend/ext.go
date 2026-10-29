package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// ext (freplace) programs (bpf-mlir v1.11.0's kind ext):
//
//	//gobpf:ext tgt g
//	func repG(ctx *bpf.ExtContext) uint32 { x := bpf.ExtArg[uint32](ctx, 0); return x + 100 }
//	→ ebpf.program @repG "ext" attach "g" { … %x = ebpf.ext.arg %ctx[0] : !ebpf.ctx<"ext"> -> i32 … ebpf.return %r : i32 }
//
// The only replacement target is **a non-ext program `tgt` in the same package and a `//gobpf:global` function `g` it calls (directly or via subprograms)**
// (gobpf.Load makes a program of the same Load the AttachTarget — there is no API taking another program's fd). The kernel's bpf_check_attach_target refuses
// static functions with "Cannot replace static functions" and functions missing from the target program's func_info with "Subprog doesn't exist" —
// the frontend stops the same shapes first, with a position. Signatures must be **identical** Go types (the kernel's btf_check_func_type_match compares only the BTF kind of the result and the
// kind and size of the arguments, not signedness or the result width — from reading the kernel source). Arguments and results are integers only (bpf-mlir's ext.arg and ret),
// at most 5 arguments (ext.arg index 0..4 — the BPF function argument limit). The schema args / ret are **unsigned** of the same width (ebpf-compile emits unsigned integers
// in a global function's BTF — matching gobpf's ExtTargets, which checks the requirements' extarg / extret against the target's BTF).

// extMaxArgs is the ext.arg index limit + 1 (bpf-mlir's ebpf.ext.arg — 0..4).
const extMaxArgs = 5

// extDirective checks `//gobpf:ext <program> <function>` and returns the function name as the attach (the program name goes to a.extTargetOf — the content is checked by
// checkExtPrograms after all programs and domains).
func (a *analyzer) extDirective(fd *ast.FuncDecl, at token.Pos, fields []string) (string, int, bool) {
	if len(fields) != 2 || !cIdent.MatchString(fields[0]) || !cIdent.MatchString(fields[1]) {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:ext takes the program whose function is replaced and the //gobpf:global function it calls (`%s`), got %v", directiveUsage("ext"), fields)
		return "", 0, false
	}
	a.extTargetOf[fd] = fields[0]
	a.extDirPos[fd] = at
	return fields[1], 0, true
}

// checkExtPrograms checks the replacement targets of ext programs: the program is a non-ext program of the same package, the function is
// a same-package function marked `//gobpf:global` reachable from that program, its arguments and result are integers (at most 5 arguments), and the ext result type is
// identical to the function's result type. Errors are GB008 at the directive position.
func (a *analyzer) checkExtPrograms() {
	for _, p := range a.programs {
		if p.ProgramType != "ext" || p.ExtTarget == "" || p.Attach == "" {
			continue // directive shape errors were already reported
		}
		at := a.extDirPos[p.decl]
		bad := func(format string, args ...any) {
			a.report(Rejected, GB008ProgramShape, at, []string{p.Symbol}, format, args...)
		}
		var tgt *Program
		for _, q := range a.programs {
			if q.Symbol == p.ExtTarget {
				tgt = q
			}
		}
		if tgt == nil || tgt.ProgramType == "ext" {
			what := "is not a program of this package"
			if tgt != nil {
				what = "is an ext program (the kernel cannot extend an extension — \"Cannot recursively attach\")"
			}
			bad("//gobpf:ext %s %s: %s %s — the replaced function must belong to a non-ext program of the same package (gobpf replaces only the test's own programs)", p.ExtTarget, p.Attach, p.ExtTarget, what)
			continue
		}
		fn, _ := a.pkg.Types.Scope().Lookup(p.Attach).(*types.Func)
		if fn == nil {
			bad("//gobpf:ext %s %s: no function named %s in this package", p.ExtTarget, p.Attach, p.Attach)
			continue
		}
		if _, global := a.globalFuncs[fn]; !global {
			bad("//gobpf:ext %s %s: %s is not marked //gobpf:global — the kernel replaces only global functions (\"Cannot replace static functions\")", p.ExtTarget, p.Attach, p.Attach)
			continue
		}
		if !a.reachesByName(tgt.Symbol, fn.Name()) {
			bad("//gobpf:ext %s %s: program %s does not call %s — the kernel finds the function in the replaced program's own functions (\"Subprog doesn't exist\")", p.ExtTarget, p.Attach, tgt.Symbol, p.Attach)
			continue
		}
		sig := fn.Type().(*types.Signature)
		var args []IntType
		ok := sig.Params().Len() <= extMaxArgs && sig.Results().Len() == 1
		for i := 0; ok && i < sig.Params().Len(); i++ {
			it, isInt := intTypeOf(sig.Params().At(i).Type())
			ok = isInt
			args = append(args, it)
		}
		if ok {
			_, ok = intTypeOf(sig.Results().At(0).Type())
		}
		if !ok {
			bad("//gobpf:ext %s %s: %s must take at most %d integer arguments and return one integer (bpf-mlir's ext reads integer arguments only — ebpf.ext.arg), got %s", p.ExtTarget, p.Attach, p.Attach, extMaxArgs, sig)
			continue
		}
		own := p.obj.Type().(*types.Signature).Results().At(0).Type()
		if !types.Identical(own, sig.Results().At(0).Type()) {
			bad("//gobpf:ext %s %s: the ext program %s returns %s but %s returns %s — the result types must be identical", p.ExtTarget, p.Attach, p.Symbol, own, p.Attach, sig.Results().At(0).Type())
			continue
		}
		p.extFunc, p.extArgs, p.Nargs = fn, args, len(args)
	}
}

// reachesByName reports whether function to is reachable from the body of program from via same-package call edges (computeDomains' graph).
func (a *analyzer) reachesByName(from, to string) bool {
	seen := map[string]bool{from: true}
	work := []string{from}
	for len(work) > 0 {
		n := work[0]
		work = work[1:]
		for _, e := range a.graph.Edges {
			if e.From != n || seen[e.To] {
				continue
			}
			if e.To == to {
				return true
			}
			seen[e.To] = true
			work = append(work, e.To)
		}
	}
	return false
}

// extArg turns `bpf.ExtArg[T](ctx, i)` into ebpf.ext.arg. handled reports whether e is that call.
func (l *lowerer) extArg(e *ast.CallExpr) (value, bool, bool) {
	if l.callOp(e) != "ext_arg" {
		return value{}, false, false
	}
	if l.progKind == nil || l.prog == nil || l.progKind.Kind != "ext" {
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "bpf.ExtArg may only be called in the body of an ext program (func f(ctx *bpf.ExtContext) T with //gobpf:ext <program> <function>) — a subprogram cannot take the context")
		return value{}, false, true
	}
	if id, ok := ast.Unparen(e.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[id] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, e.Args[0].Pos(), "the first argument of bpf.ExtArg must be the program's context parameter")
		return value{}, false, true
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB018LoopShape, e.Pos(), "bpf.ExtArg cannot be called inside a loop — read the argument before the loop")
		return value{}, false, true
	}
	fn := l.prog.extFunc
	if fn == nil { // checkExtPrograms already reported the target error
		l.failed = true
		return value{}, false, true
	}
	tv := l.a.info.Types[e.Args[1]]
	if tv.Value == nil {
		l.fail(Rejected, GB006NonConstant, e.Args[1].Pos(), "the index of bpf.ExtArg must be a constant")
		return value{}, false, true
	}
	sig := fn.Type().(*types.Signature)
	i, exact := constant.Int64Val(constant.ToInt(tv.Value))
	if !exact || i < 0 || i >= int64(sig.Params().Len()) {
		l.fail(Rejected, GB008ProgramShape, e.Args[1].Pos(), "bpf.ExtArg index %s is outside the %d arguments of %s", tv.Value.ExactString(), sig.Params().Len(), fn.Name())
		return value{}, false, true
	}
	want := sig.Params().At(int(i)).Type()
	inst, found := l.a.info.Instances[tpArgIdent(e)]
	if !found || inst.TypeArgs == nil || inst.TypeArgs.Len() < 1 || !types.Identical(inst.TypeArgs.At(0), want) {
		got := "?"
		if found && inst.TypeArgs != nil && inst.TypeArgs.Len() >= 1 {
			got = inst.TypeArgs.At(0).String()
		}
		l.fail(Rejected, GB008ProgramShape, e.Pos(), "bpf.ExtArg[%s](ctx, %d): argument %d of %s is %s — the type argument must be identical", got, i, i, fn.Name(), want)
		return value{}, false, true
	}
	it := l.prog.extArgs[i]
	defer l.at(e.Pos())()
	r := l.val()
	l.emit("%s = ebpf.ext.arg %%ctx[%d] : !ebpf.ctx<\"ext\"> -> %s", r, i, it.mlir())
	return value{r, vtypeOf(it)}, true, true
}

// returnForm is the shape of the program's final return value (for diagnostics — for ext a value of the replaced function's result type, otherwise a constant of the verdict type).
func (k *ctxKind) returnForm() string {
	if k.Kind == "ext" {
		return "a value of the replaced function's result type"
	}
	if k.Kind == "struct_ops" {
		return "a uint32 value (the member's result)"
	}
	return "bpf." + k.Action + " constant"
}

// retVType is the return type of an IntRetExpr kind (for ext, the Go integer type of the program's result; otherwise i32).
func (l *lowerer) retVType() vtype {
	if l.prog != nil && (l.prog.ProgramType == "ext" || l.prog.ProgramType == "struct_ops") && l.prog.Ret != nil { // struct_ops — the u32 of the member table
		return vtypeOf(*l.prog.Ret)
	}
	return vtype{bits: 32, signed: true}
}

// extSchemaArgs returns the schema args of an ext program (unsigned of the same width as the replaced function's argument types — see the note above).
func (p *Program) extSchemaArgs() []any {
	out := []any{}
	for _, it := range p.extArgs {
		out = append(out, schemaIntOf(IntType{Bits: it.Bits}))
	}
	return out
}
