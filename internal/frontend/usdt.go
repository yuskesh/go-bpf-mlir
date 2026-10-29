package frontend

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// usdt (bpf-mlir's usdt):
//
//	//gobpf:usdt fixture/usfix us:hit
//	func onHit(ctx *bpf.USDTContext) {
//		i := bpf.ProbeTargetIndex(ctx)       → %v = ebpf.probe.target_index %ctx : !ebpf.ctx<"usdt"> -> i64
//		a, st := bpf.USDTArg[int64](ctx, 1)  → %v:2 = ebpf.usdt.arg %ctx 1 : !ebpf.ctx<"usdt"> -> i64, i64
//	}
//
// The declaration is `ebpf.program @onHit "usdt" attach "us:hit" arch "x86_64"`; the schema has binary_sha256, semaphore (required if the note
// points have a semaphore), max_points (the number of points in the binary — the size of the compiler's spec map `__ebpf_usdt_spec_<program>`) and params. The path is used only by generate
// (the same rule as uprobe). The presence of note points, consistent semaphores, and the number and size / sign of USDTArg arguments are checked at generate time (the check before load does the same).

// USDTSpecMap is the name of the spec map the compiler emits for each usdt program that uses USDTArg (bpf-mlir's requirements.USDTSpecMapPrefix +
// program — outside the user's map name space: the reserved prefix `__` cannot be written as a Go map name).
func USDTSpecMap(program string) string { return requirements.USDTSpecMapPrefix + program }

// usdtDirective reads the two words of `//gobpf:usdt <path> <provider>:<name>`.
func (a *analyzer) usdtDirective(fd *ast.FuncDecl, at token.Pos, fields []string) (string, int, bool) {
	if len(fields) != 2 || !usdtTarget.MatchString(fields[1]) {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:usdt takes the binary's path (relative to the package directory — used only at generate time) and the USDT point as `<provider>:<name>` (C identifiers): `//gobpf:usdt <path> <provider>:<name>`, got %q", strings.Join(fields, " "))
		return "", 0, false
	}
	a.uprobeDecl[fd] = uprobeDirectiveInfo{path: fields[0], pos: at}
	return fields[1], 0, true
}

// checkUSDTBinaries reads the binary of each usdt program at generate time: sha256, the note points (provider:name — at least one), and that every point
// agrees on having a semaphore. The schema's semaphore and max_points come from the notes (the binary is the source of truth — not copied into the directive).
func (a *analyzer) checkUSDTBinaries() {
	for _, p := range a.programs {
		if p.ProgramType != "usdt" {
			continue
		}
		d, ok := a.uprobeDecl[p.decl]
		if !ok {
			continue // the directive error is already reported
		}
		p.Binary, p.dirPos = d.path, d.pos
		fail := func(format string, args ...any) {
			a.report(Rejected, GB008ProgramShape, d.pos, []string{p.Symbol}, "usdt program %s: "+format, append([]any{p.Symbol}, args...)...)
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
		h := sha256.New()
		_, herr := io.Copy(h, f)
		ef, eerr := elf.NewFile(f)
		var points []requirements.USDTPoint
		if herr == nil && eerr == nil {
			points, err = requirements.ReadUSDTPoints(ef)
		}
		f.Close()
		switch {
		case herr != nil:
			fail("%s: %v", d.path, herr)
			continue
		case eerr != nil:
			fail("%s is not an ELF file: %v", d.path, eerr)
			continue
		case err != nil:
			fail("%s: the stapsdt notes cannot be read: %v", d.path, err)
			continue
		}
		provider, name, _ := strings.Cut(p.Attach, ":")
		var mine []requirements.USDTPoint
		for _, pt := range points {
			if pt.Provider == provider && pt.Name == name {
				mine = append(mine, pt)
			}
		}
		if len(mine) == 0 {
			fail("%s has no USDT point %s (%d points of other probes in its stapsdt notes)", d.path, p.Attach, len(points))
			continue
		}
		sem := mine[0].Semaphore != 0
		for _, pt := range mine[1:] {
			if (pt.Semaphore != 0) != sem {
				fail("the points of %s in %s disagree on the semaphore (pc 0x%x has %#x, pc 0x%x has %#x) — one program declares one semaphore mode", p.Attach, d.path, mine[0].PC, mine[0].Semaphore, pt.PC, pt.Semaphore)
				sem = false
				mine = nil
				break
			}
		}
		if mine == nil {
			continue
		}
		p.BinarySHA256 = hex.EncodeToString(h.Sum(nil))
		p.USDTSemaphore = map[bool]string{true: "required", false: "none"}[sem]
		p.USDTMaxPoints, p.usdtPoints = len(mine), mine
	}
}

// checkUSDTParams checks the n and type of each USDTArg collected by lowering against the note argument specs (`<±size>@<location>`) of every point in the binary (at generate time —
// the usdtarg check before load does the same). It reports only the first mismatch.
func (a *analyzer) checkUSDTParams() {
	for _, p := range a.programs {
		if p.ProgramType != "usdt" || p.BinarySHA256 == "" {
			continue
		}
		for _, n := range p.paramOrder() {
			want := p.Params[n]
			for _, pt := range p.usdtPoints {
				args := strings.Fields(pt.Args)
				if n > len(args) {
					a.report(Rejected, GB008ProgramShape, p.paramPos[n], []string{p.Symbol}, "usdt program %s reads argument %d of %s, but the point at pc 0x%x has %d arguments (%q)", p.Symbol, n, p.Attach, pt.PC, len(args), pt.Args)
					break
				}
				spec, sizeOK, err := requirements.ParseUSDTArg(args[n-1])
				if !sizeOK {
					a.report(Rejected, GB008ProgramShape, p.paramPos[n], []string{p.Symbol}, "usdt program %s reads argument %d of %s, but the point at pc 0x%x describes it as %q: %v", p.Symbol, n, p.Attach, pt.PC, args[n-1], err)
					break
				}
				if spec.Size*8 != want.Bits || spec.Signed != want.Signed {
					got := IntType{Bits: spec.Size * 8, Signed: spec.Signed}
					a.report(Rejected, GB008ProgramShape, p.paramPos[n], []string{p.Symbol}, "usdt program %s reads argument %d of %s as %s, but the point at pc 0x%x describes it as %q (%s)", p.Symbol, n, p.Attach, goIntName(want), pt.PC, args[n-1], goIntName(got))
					break
				}
			}
		}
	}
}

// usdtArgAssign lowers `v, st := bpf.USDTArg[T](ctx, n)` (`_` allowed in either) to `%r:2 = ebpf.usdt.arg %ctx n : !ebpf.ctx<"usdt"> -> iW, i64`.
// handled reports whether the right-hand side of s is USDTArg.
func (l *lowerer) usdtArgAssign(s *ast.AssignStmt) bool {
	if len(s.Rhs) != 1 {
		return false
	}
	call, ok := ast.Unparen(s.Rhs[0]).(*ast.CallExpr)
	if !ok || l.callOp(call) != "usdt_arg" {
		return false
	}
	const fn = "bpf.USDTArg"
	defer l.at(call.Pos())()
	if l.calleeAttach(call.Pos(), fn) { // a subprogram that takes the context
		return true
	}
	if l.progKind == nil || l.progKind.Kind != "usdt" || l.prog == nil {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s may only be used in the body of a usdt program (func f(ctx *bpf.USDTContext) with //gobpf:usdt <path> <provider>:<name>)", fn)
		return true
	}
	if s.Tok != token.DEFINE && s.Tok != token.ASSIGN {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
		return true
	}
	if cid, ok := ast.Unparen(call.Args[0]).(*ast.Ident); !ok || l.a.info.Uses[cid] != l.ctxVar {
		l.fail(Rejected, GB008ProgramShape, call.Args[0].Pos(), "the first argument of %s must be the program's context parameter", fn)
		return true
	}
	n, ok := l.usdtArgNumber(call.Args[1])
	if !ok {
		return true
	}
	it, isInt := IntType{}, false
	if tup, ok := l.a.info.Types[call].Type.(*types.Tuple); ok && tup.Len() == 2 {
		it, isInt = intTypeOf(tup.At(0).Type())
	}
	if !isInt {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s reads an 8 / 16 / 32 / 64-bit integer", fn)
		return true
	}
	p := l.prog
	if p.Params == nil {
		p.Params, p.paramPos = map[int]IntType{}, map[int]token.Pos{}
	}
	if prev, seen := p.Params[n]; seen && prev != it {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "argument %d of the usdt program %s is read as %s here but as %s at %s — one argument has one type (schema params)", n, p.Symbol, goIntName(it), goIntName(prev), posString(l.a.position(p.paramPos[n])))
		return true
	} else if !seen {
		p.Params[n], p.paramPos[n] = it, call.Pos()
	}
	p.USDTSpec = true
	t := vtypeOf(it)
	r := l.val()
	l.emit("%s:2 = ebpf.usdt.arg %%ctx %d : !ebpf.ctx<\"usdt\"> -> %s, i64", r, n, t.mlir())
	results := []value{{r + "#0", t}, {r + "#1", vtype{bits: 64, signed: true}}}
	for i, lhs := range s.Lhs {
		id, _ := lhs.(*ast.Ident)
		if id == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, lhs.Pos(), "assignment target must be a local variable")
			return true
		}
		if id.Name == "_" {
			continue
		}
		v := l.localVar(id, s.Tok == token.DEFINE)
		if v == nil {
			l.fail(Unknown, GB001UnsupportedConstruct, id.Pos(), "assignment target %s must be a local variable", id.Name)
			return true
		}
		l.setVar(id, v, results[i])
	}
	return true
}

// usdtArgNumber returns the argument number of USDTArg (a constant 1 to 12 — the n of bpf-mlir's ebpf.usdt.arg).
func (l *lowerer) usdtArgNumber(e ast.Expr) (int, bool) {
	tv := l.a.info.Types[e]
	if tv.Value != nil {
		if n, exact := constant.Int64Val(constant.ToInt(tv.Value)); exact && n >= 1 && n <= 12 {
			return int(n), true
		}
	}
	l.fail(Rejected, GB008ProgramShape, e.Pos(), "the argument number of bpf.USDTArg must be a constant 1..12 (a USDT point describes up to 12 arguments)")
	return 0, false
}
