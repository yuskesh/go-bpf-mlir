package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// Variable indexes into array fields of records.
//
// Go's `p.Arr[i]` panics when out of range, but BPF has no panic — the out_of_range of bpf-mlir's `ebpf.ref.index` is mapped to a user branch:
//
//	shape A: if i < uint32(len(p.Arr)) { … p.Arr[i] … } [else { … }]
//	      → ref.index %borrow "arr" [%i] in_range(%e) { then — p.Arr[i] is elem.load / elem.store %e } out_of_range { else }
//	shape B: for i := range uint32(N) { if p := M.Lookup(k); p != nil { … p.Arr[i] … } }   (N ≤ len(p.Arr) — the range is guaranteed by structure)
//	      → a ref.index per read or write (out_of_range is unreachable)
//
// An unchecked `p.Arr[i]` stops with an error (never a silent 0 / clamp).
//
// Chains may nest (`p.A.Arr[i]`, `p.Arr[i].F`, `p.M[i][j]` — paths "a.arr[]", "arr[].f", "m[][]"). Shape A for arrays of integer elements is unchanged
// (ref.index as the if); range checks for arrays of records or arrays of arrays use shape A′ (nested.go's rangeGuardIf — a plain ebpf.if and a ref.index per read or write).

// indexGuard is the checked element inside the then arm of shape A.
type indexGuard struct {
	obj    *types.Var // the checked record pointer (checked.obj)
	prefix string     // the path of the checked array ("arr", "a.arr")
	iv     *types.Var // the index variable
	elem   string     // the in_range block argument (!ebpf.elem<iN>)
}

// dynAccess is the resolution of a variable-index leaf.
type dynAccess struct {
	ref   *checkedRef // the checked borrow at the root (outer or inner)
	path  string      // the ref.index path (variable indexes are [])
	elemT IntType
	guard *indexGuard  // shape A (nil means a ref.index per read or write)
	idx   []*types.Var // the indexes of the per-access ref.index (chain order — loop counters or shape A′ checked variables)
	notes []string     // why out_of_range is unreachable (comment)
}

// dynField resolves e if it is a variable-index leaf of a checked record. If handled is false, e is not this shape (fieldPath reports unproven indexes).
func (l *lowerer) dynField(e ast.Expr) (d dynAccess, ok, handled bool) {
	if _, isIx := e.(*ast.IndexExpr); !isIx {
		if _, isSel := e.(*ast.SelectorExpr); !isSel {
			return d, false, false
		}
	}
	acc, aok, ah := l.walkAccess(e, false)
	if !ah || !aok || acc.end.Kind != ABIInt || len(acc.vars) == 0 || acc.ref == nil || acc.ref.rec == nil {
		return d, false, false
	}
	d.ref, d.path, d.elemT = acc.ref, acc.path, *acc.end.Int
	if g := l.guard; g != nil && len(acc.vars) == 1 {
		if v := acc.vars[0]; v.iv != nil && g.iv == v.iv && g.obj == acc.ref.obj && g.prefix == v.prefix && acc.path == v.prefix+"[]" {
			d.guard = g
			return d, true, true
		}
	}
	for _, v := range acc.vars {
		if v.iv == nil {
			return d, false, false
		}
		proved := false
		for i := len(l.rguards) - 1; i >= 0 && !proved; i-- {
			if g := l.rguards[i]; g.iv == v.iv && g.obj == acc.ref.obj && g.prefix == v.prefix {
				d.notes = append(d.notes, g.note())
				proved = true
			}
		}
		for _, lc := range l.loops {
			if proved || lc.iv != v.iv {
				continue
			}
			if uint64(lc.count) > v.count {
				x := types.ExprString(v.arr)
				l.fail(Rejected, GB014WindowIndex, v.e.Pos(), "the loop counter %s runs to %d, beyond len(%s) = %d — check it (`if %s < uint32(len(%s)) { … }`)", v.iv.Name(), lc.count, x, v.count, v.iv.Name(), x)
				return d, false, true
			}
			d.notes = append(d.notes, fmt.Sprintf("loop count %d <= len(%s) = %d", lc.count, v.prefix, v.count))
			proved = true
		}
		if !proved {
			return d, false, false // fieldPath reports the "non-constant index" error
		}
		d.idx = append(d.idx, v.iv)
	}
	return d, true, true
}

func (l *lowerer) elemType(d dynAccess) string { return fmt.Sprintf("!ebpf.elem<%s>", d.elemT.mlir()) }

// indexOperands returns the index values and types of a per-access ref.index.
func (l *lowerer) indexOperands(d dynAccess) (names, types string) {
	var ns []string
	for _, iv := range d.idx {
		ns = append(ns, l.env[iv].name)
	}
	return strings.Join(ns, ", "), strings.Repeat(", i32", len(d.idx))
}

// unreachableNote is the comment for an unreachable out_of_range (not an implicit 0 — the frontend already checked the index range in dynField).
func (d dynAccess) unreachableNote() string {
	return "// unreachable: " + strings.Join(d.notes, "; ") + " (checked by the frontend)\n"
}

// dynLoad reads an element at a variable index.
func (l *lowerer) dynLoad(d dynAccess) value {
	r := l.val()
	if d.guard != nil {
		l.emit("%s = ebpf.elem.load %s : %s -> %s", r, d.guard.elem, l.elemType(d), d.elemT.mlir())
		return value{r, vtypeOf(d.elemT)}
	}
	// A per-access ref.index: the index is in range by structure (the loop count) or an enclosing range check — out_of_range is unreachable (it yields 0).
	idx, idxT := l.indexOperands(d)
	e := l.val()
	in := l.region(func() {
		x := l.val()
		l.emit("%s = ebpf.elem.load %s : %s -> %s", x, e, l.elemType(d), d.elemT.mlir())
		l.emit("ebpf.yield %s : %s", x, d.elemT.mlir())
	})
	out := l.region(func() {
		l.b.WriteString(l.indent + d.unreachableNote())
		z := l.constant(constant.MakeInt64(0), vtypeOf(d.elemT))
		l.emit("ebpf.yield %s : %s", z.name, d.elemT.mlir())
	})
	l.b.WriteString(fmt.Sprintf("%s%s = ebpf.ref.index %s %q [%s] : %s%s -> %s in_range {\n%s^in(%s: %s):\n%s%s} out_of_range {\n%s%s}%s\n",
		l.indent, r, d.ref.borrow, indexTemplate(d.path, len(d.idx)), idx, borrowType(d.ref), idxT, d.elemT.mlir(), l.indent, e, l.elemType(d), in, l.indent, out, l.indent, l.locSuffix(l.pos)))
	return value{r, vtypeOf(d.elemT)}
}

// dynStore writes an element at a variable index (a per-access ref.index except for shape A).
func (l *lowerer) dynStore(d dynAccess, v value) {
	if d.guard != nil {
		l.emit("ebpf.elem.store %s, %s : %s, %s", d.guard.elem, v.name, l.elemType(d), d.elemT.mlir())
		return
	}
	idx, idxT := l.indexOperands(d)
	e := l.val()
	in := l.region(func() {
		l.emit("ebpf.elem.store %s, %s : %s, %s", e, v.name, l.elemType(d), d.elemT.mlir())
		l.emit("ebpf.yield")
	})
	out := l.region(func() {
		l.b.WriteString(l.indent + d.unreachableNote())
		l.emit("ebpf.yield")
	})
	l.b.WriteString(fmt.Sprintf("%sebpf.ref.index %s %q [%s] : %s%s in_range {\n%s^in(%s: %s):\n%s%s} out_of_range {\n%s%s}%s\n",
		l.indent, d.ref.borrow, indexTemplate(d.path, len(d.idx)), idx, borrowType(d.ref), idxT, l.indent, e, l.elemType(d), in, l.indent, out, l.indent, l.locSuffix(l.pos)))
}

// isIndexGuard reports whether s is a range check `if i < uint32(len(<array>))` (the array is a chain, possibly nested, from the current checked record pointer).
func (l *lowerer) isIndexGuard(s *ast.IfStmt) (iv *types.Var, arr recordAccess, ok bool) {
	if s.Init != nil || len(l.borrows) == 0 {
		return nil, arr, false
	}
	be, isBin := s.Cond.(*ast.BinaryExpr)
	if !isBin || be.Op != token.LSS {
		return nil, arr, false
	}
	iid, _ := be.X.(*ast.Ident)
	if iid == nil {
		return nil, arr, false
	}
	iv = l.localVar(iid, false)
	y := be.Y
	for {
		if p, isParen := y.(*ast.ParenExpr); isParen {
			y = p.X
			continue
		}
		if c, isCall := y.(*ast.CallExpr); isCall && l.a.info.Types[c.Fun].IsType() && len(c.Args) == 1 {
			y = c.Args[0]
			continue
		}
		break
	}
	call, isCall := y.(*ast.CallExpr)
	if !isCall || len(call.Args) != 1 {
		return nil, arr, false
	}
	if b, isB := l.a.info.Uses[identOf(call.Fun)].(*types.Builtin); !isB || b.Name() != "len" {
		return nil, arr, false
	}
	acc, aok, ah := l.walkAccess(call.Args[0], false)
	if !ah || !aok || acc.root == nil || acc.ref == nil || acc.ref.rec == nil || acc.end.Kind != ABIArray || iv == nil {
		return nil, arr, false
	}
	return iv, acc, true
}

func identOf(e ast.Expr) *ast.Ident {
	id, _ := e.(*ast.Ident)
	return id
}

// indexGuardIf turns a shape A if (an array of integer elements with no variable index on its path) into ref.index (then = in_range, else = out_of_range, with a merge of outer variables).
func (l *lowerer) indexGuardIf(s *ast.IfStmt, iv *types.Var, arr recordAccess) {
	if b, isB := iv.Type().Underlying().(*types.Basic); !isB || b.Kind() != types.Uint32 {
		l.fail(Rejected, GB014WindowIndex, s.Cond.Pos(), "the index %s must be uint32 (ebpf.ref.index compares unsigned — a negative int32 index panics in Go but is out of range in BPF)", iv.Name())
		return
	}
	if l.guard != nil {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "a range check inside another range check is not supported yet")
		return
	}
	// Assigning the index variable in the then arm would make the checked value differ from the value read.
	var assigned token.Pos
	ast.Inspect(s.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && l.a.info.Uses[id] == iv {
					assigned = id.Pos()
				}
			}
		case *ast.IncDecStmt:
			if id, ok := n.X.(*ast.Ident); ok && l.a.info.Uses[id] == iv {
				assigned = id.Pos()
			}
		case *ast.BranchStmt:
			l.fail(Rejected, GB018LoopShape, n.Pos(), "%s cannot be inside a range check (bpf-mlir: break / continue leave only ebpf.if / ebpf.ref.check arms)", n.Tok)
		}
		return true
	})
	if assigned.IsValid() {
		l.fail(Rejected, GB014WindowIndex, assigned, "the checked index %s must not be assigned inside the range check", iv.Name())
	}
	var elseBlock *ast.BlockStmt
	if s.Else != nil {
		eb, isBlock := s.Else.(*ast.BlockStmt)
		if !isBlock {
			l.fail(Unknown, GB001UnsupportedConstruct, s.Else.Pos(), "else-if is not supported after a range check")
			return
		}
		elseBlock = eb
	}
	if l.failed {
		return
	}
	idx := l.env[iv]
	elem := l.val()
	before := copyEnv(l.env)
	l.env = copyEnv(before)
	l.guard = &indexGuard{obj: arr.ref.obj, prefix: arr.path, iv: iv, elem: elem}
	inText := l.region(func() { l.stmts(s.Body.List) })
	l.guard = nil
	inEnv := l.env
	l.env = copyEnv(before)
	outText := ""
	if elseBlock != nil {
		outText = l.region(func() { l.stmts(elseBlock.List) })
	}
	outEnv := l.env
	if l.failed {
		return
	}
	mods := mergeVars(before, inEnv, outEnv)
	outPos := s.Body.Rbrace
	if elseBlock != nil {
		outPos = elseBlock.Rbrace
	}
	l.yieldInto(&inText, inEnv, mods, "ebpf.yield", s.Body.Rbrace)
	l.yieldInto(&outText, outEnv, mods, "ebpf.yield", outPos)
	l.env = before
	head, typeList, base := l.resultHead(mods, before)
	elemT := fmt.Sprintf("!ebpf.elem<%s>", arr.end.Array.Elem.Int.mlir())
	l.b.WriteString(fmt.Sprintf("%s%sebpf.ref.index %s %q [%s] : %s, i32%s in_range {\n%s^in(%s: %s):\n%s%s} out_of_range {\n%s%s}%s\n",
		l.indent, head, arr.ref.borrow, arr.path, idx.name, borrowType(arr.ref), typeList, l.indent, elem, elemT, inText, l.indent, outText, l.indent, l.locSuffix(s.Pos())))
	if base != "" {
		l.bindResults(mods, before, base)
	}
}

// loopCount returns the count of the loop enclosing the loop variable iv.
func (l *lowerer) loopCount(iv *types.Var) int64 {
	for _, lc := range l.loops {
		if lc.iv == iv {
			return lc.count
		}
	}
	return -1
}
