package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// Field paths of nested records.
//
//	p.A.B          → "a.b"            p.Arr[2].F → "arr[2].f"        p.M[1][0] → "m[1][0]"
//	p.Arr[i].F     → "arr[].f" (ref.index — i proven by a range check or a loop counter)
//
// It follows the selector and index chain from a checked record pointer p to a leaf (an integer), and builds bpf-mlir's path (RecordPath — components ≤ 3, array dimensions ≤ 2;
// recordOf stops the limits at the record declaration) and the offset from the start of the record. A nested record or an array itself (not a leaf) is never a value.

// recordAccess is a resolved chain.
type recordAccess struct {
	ref    *checkedRef // the checked borrow at the root (outer or inner)
	root   *ast.Ident
	path   string    // bpf-mlir's path ([N] for a constant index, [] for a variable index)
	offset uint64    // the byte offset from the start of the record (a variable index counts as element 0)
	end    SharedABI // the last type of the chain (ABIInt for a leaf)
	vars   []varIndex
}

// varIndex is a variable index in the chain.
type varIndex struct {
	e      ast.Expr   // the index expression
	iv     *types.Var // if the index is a local variable
	arr    ast.Expr   // the array expression (for diagnostics — p.Arr)
	count  uint64     // the number of array elements
	prefix string     // the path of the array itself (matched against range checks — "a.arr")
}

// rangeGuard is the then arm of a range check `if i < uint32(len(p.Arr)) { … }` on a record array (elements are records or arrays) (shape A′).
// The if is a plain ebpf.if (len is a constant), and p.Arr[i].F in the arm is a ref.index per read / write (out_of_range is unreachable by the check).
type rangeGuard struct {
	obj    *types.Var // the checked record pointer
	iv     *types.Var
	prefix string
	count  uint64
}

// recordChain returns the selector and index chain of e in order from the root identifier (nil if not a chain).
func recordChain(e ast.Expr) (*ast.Ident, []ast.Expr) {
	var steps []ast.Expr
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
		case *ast.SelectorExpr:
			steps = append(steps, x)
			e = x.X
		case *ast.IndexExpr:
			steps = append(steps, x)
			e = x.X
		case *ast.Ident:
			for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
				steps[i], steps[j] = steps[j], steps[i]
			}
			return x, steps
		default:
			return nil, nil
		}
	}
}

// walkAccess resolves e if it is a chain from a checked record pointer. If handled is false, e does not have this shape (left to the caller's other branches).
// If report is false it returns ok = false without reporting (a dry run for dynField — fieldPath reports later).
func (l *lowerer) walkAccess(e ast.Expr, report bool) (acc recordAccess, ok, handled bool) {
	root, steps := recordChain(e)
	if root == nil || len(steps) == 0 {
		return acc, false, false
	}
	first, isSel := steps[0].(*ast.SelectorExpr)
	if !isSel {
		return acc, false, false
	}
	fail := func(k Verdict, code Code, at ast.Node, format string, args ...any) (recordAccess, bool, bool) {
		if report {
			l.fail(k, code, at.Pos(), format, args...)
		}
		return acc, false, true
	}
	pv, _ := l.a.info.Uses[root].(*types.Var)
	if pv == nil {
		return acc, false, false
	}
	c := l.borrowOf(pv)
	if c == nil {
		// a field of a local pointer — outside the checked branch (rejectUses stops the else arm first).
		if _, isPtr := pv.Type().(*types.Pointer); isPtr && l.localVar(root, false) != nil {
			return fail(Rejected, GB005NilCheckShape, first, "%s.%s outside the `%s != nil` branch", root.Name, first.Sel.Name, root.Name)
		}
		return acc, false, false
	}
	rec := c.record()
	if rec == nil {
		return fail(Unknown, GB001UnsupportedConstruct, first, "%s points to an integer; use *%s", root.Name, root.Name)
	}
	acc.ref, acc.root = c, root
	cur := *rec
	var sb strings.Builder
	for _, st := range steps {
		switch st := st.(type) {
		case *ast.SelectorExpr:
			if cur.Kind != ABIRecord {
				return fail(Unknown, GB015InternalEmitter, st, "internal: %s selects a field of a non-record", types.ExprString(st))
			}
			f, found := cur.Record.fieldByGoName(st.Sel.Name)
			if !found {
				return fail(Unknown, GB001UnsupportedConstruct, st.Sel, "record %s has no schema field %s", cur.Record.Symbol, st.Sel.Name)
			}
			if f.Type.Kind == ABISpinLock || f.Type.Kind == ABITimer {
				use := "bpf.WithLock(&" + types.ExprString(st) + ", func() { … })"
				if f.Type.Kind == ABITimer {
					use = types.ExprString(st) + ".Init() / SetCallback(cb) / Start(ns)"
				}
				return fail(Rejected, GB016SharedABIShape, st, "%s is %s — it cannot be read or written as a value; use it only as %s", types.ExprString(st), specialName(f.Type.Kind), use)
			}
			if sb.Len() > 0 {
				sb.WriteByte('.')
			}
			sb.WriteString(f.Name)
			acc.offset += f.Offset
			cur = f.Type
		case *ast.IndexExpr:
			if cur.Kind != ABIArray {
				return fail(Unknown, GB001UnsupportedConstruct, st.Index, "%s is not an array", types.ExprString(st.X))
			}
			if tv := l.a.info.Types[st.Index]; tv.Value != nil {
				n, exact := constant.Uint64Val(constant.ToInt(tv.Value))
				if !exact || n >= cur.Array.Count {
					// go/types makes an out-of-range constant index a type error, so reaching here is a frontend bug.
					return fail(Unknown, GB015InternalEmitter, st.Index, "internal: index %s out of range for %s", tv.Value.ExactString(), types.ExprString(st.X))
				}
				sb.WriteString("[" + uitoa(n) + "]")
				acc.offset += n * cur.Array.Elem.Size
			} else {
				v := varIndex{e: st.Index, arr: st.X, count: cur.Array.Count, prefix: sb.String()}
				if id, isID := st.Index.(*ast.Ident); isID {
					v.iv, _ = l.a.info.Uses[id].(*types.Var)
				}
				acc.vars = append(acc.vars, v)
				sb.WriteString("[]")
			}
			cur = cur.Array.Elem
		}
	}
	acc.path, acc.end = sb.String(), cur
	return acc, true, true
}

// leafAccess requires the walkAccess chain to end at an integer leaf (an array itself or a whole nested record is not a value).
func (l *lowerer) leafAccess(e ast.Expr, report bool) (recordAccess, bool, bool) {
	acc, ok, handled := l.walkAccess(e, report)
	if !ok || !handled {
		return acc, ok, handled
	}
	switch acc.end.Kind {
	case ABIInt:
		return acc, true, true
	case ABIArray:
		if report {
			x := types.ExprString(e)
			l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "the array field %s may only be used with a constant index (%s[i] — arrays are not values in the subset)", x, x)
		}
	case ABIRecord:
		if report {
			x := types.ExprString(e)
			l.fail(Rejected, GB016SharedABIShape, e.Pos(), "%s is the nested record %s — a whole record is not a value in the subset (read and write its fields: %s.F)", x, acc.end.Record.Symbol, x)
		}
	default:
		if report {
			l.fail(Unknown, GB016SharedABIShape, e.Pos(), "field %s has an unsupported shape", types.ExprString(e))
		}
	}
	return acc, false, true
}

// indexTemplate returns the path text of ref.index (with one variable index at the end of the path the trailing [] is dropped — bpf-mlir reads "arr" and "arr[]" the same,
// keeping the generated files byte-identical to those before nested paths).
func indexTemplate(path string, nvars int) string {
	if nvars == 1 && strings.Count(path, "[") == 1 && strings.HasSuffix(path, "[]") {
		return strings.TrimSuffix(path, "[]")
	}
	return path
}

// rangeGuardIf lowers a shape A′ if (a range check on a record array or a 2-dimensional array) to a plain ebpf.if and marks the index proven in the then arm.
func (l *lowerer) rangeGuardIf(s *ast.IfStmt, iv *types.Var, arr recordAccess) {
	if b, isB := iv.Type().Underlying().(*types.Basic); !isB || b.Kind() != types.Uint32 {
		l.fail(Rejected, GB014WindowIndex, s.Cond.Pos(), "the index %s must be uint32 (ebpf.ref.index compares unsigned — a negative int32 index panics in Go but is out of range in BPF)", iv.Name())
		return
	}
	if l.guard != nil {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "a range check inside another range check is not supported yet")
		return
	}
	if p := assignedIn(l, s.Body, iv); p.IsValid() {
		l.fail(Rejected, GB014WindowIndex, p, "the checked index %s must not be assigned inside the range check", iv.Name())
		return
	}
	l.thenGuard = &rangeGuard{obj: arr.ref.obj, iv: iv, prefix: arr.path, count: arr.end.Array.Count}
	l.ifStmt(s)
	l.thenGuard = nil
}

// assignedIn returns the first position in body that assigns to iv (an invalid position if none).
func assignedIn(l *lowerer, body *ast.BlockStmt, iv *types.Var) (at token.Pos) {
	ast.Inspect(body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			for _, lhs := range n.Lhs {
				if id, ok := lhs.(*ast.Ident); ok && l.a.info.Uses[id] == iv && !at.IsValid() {
					at = id.Pos()
				}
			}
		case *ast.IncDecStmt:
			if id, ok := n.X.(*ast.Ident); ok && l.a.info.Uses[id] == iv && !at.IsValid() {
				at = id.Pos()
			}
		}
		return true
	})
	return at
}

// nestedShape reports whether t is a nested shape (a record, a record array, an array of arrays) — integers and integer arrays of a flat record keep the existing record.make path (byte-identical).
func nestedShape(t SharedABI) bool {
	switch t.Kind {
	case ABIRecord:
		return true
	case ABIArray:
		return t.Array.Elem.Kind != ABIInt
	}
	return false
}

// makeLeaves splits the value e of type t (the zero value if nil) into leaves under the path prefix and adds them (record.make takes every leaf once by its leaf path).
// A record is a composite literal with named fields, an array a literal of elements in order (indexed elements are not accepted). Omitted leaves are zero.
func (l *lowerer) makeLeaves(prefix string, t SharedABI, e ast.Expr, add func(string, value), zero func(IntType) value) bool {
	switch t.Kind {
	case ABIInt:
		if e == nil {
			add(prefix, zero(*t.Int))
			return true
		}
		vt := vtypeOf(*t.Int)
		v, ok := l.expr(e, &vt)
		if !ok {
			return false
		}
		add(prefix, v)
		return true
	case ABIArray:
		var elts []ast.Expr
		if e != nil {
			cl, isCL := ast.Unparen(e).(*ast.CompositeLit)
			if !isCL {
				l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "the array %s must be given as an array literal ([N]T{…}) in a record literal", prefix)
				return false
			}
			for _, el := range cl.Elts {
				if _, isKV := el.(*ast.KeyValueExpr); isKV {
					l.fail(Unknown, GB001UnsupportedConstruct, el.Pos(), "indexed elements in an array literal are not supported; list the elements in order")
					return false
				}
			}
			elts = cl.Elts
		}
		for i := uint64(0); i < t.Array.Count; i++ {
			var el ast.Expr
			if i < uint64(len(elts)) {
				el = elts[i]
			}
			if !l.makeLeaves(indexPath(prefix, i), t.Array.Elem, el, add, zero) {
				return false
			}
		}
		return true
	case ABIRecord:
		given := map[string]ast.Expr{}
		if e != nil {
			cl, isCL := ast.Unparen(e).(*ast.CompositeLit)
			if !isCL || !types.Identical(l.a.info.Types[cl].Type, t.GoType) {
				l.fail(Rejected, GB016SharedABIShape, e.Pos(), "the nested record %s must be given as a composite literal %s{…} (a whole record is not a value in the subset)", prefix, t.Record.Symbol)
				return false
			}
			for _, el := range cl.Elts {
				kv, isKV := el.(*ast.KeyValueExpr)
				if !isKV {
					l.fail(Unknown, GB001UnsupportedConstruct, el.Pos(), "a record literal must name its fields (%s{F: e, …})", t.Record.Symbol)
					return false
				}
				given[kv.Key.(*ast.Ident).Name] = kv.Value
			}
		}
		for _, f := range t.Record.Fields {
			if !l.makeLeaves(prefix+"."+f.Name, f.Type, given[f.GoName], add, zero) {
				return false
			}
		}
		return true
	}
	at := l.pos
	if e != nil {
		at = e.Pos()
	}
	l.fail(Unknown, GB016SharedABIShape, at, "field %s has an unsupported shape in a record literal", prefix)
	return false
}

// rangeGuardNote is a comment for an unreachable out_of_range of ref.index.
func (g *rangeGuard) note() string {
	return fmt.Sprintf("%s < len(%s) = %d by the enclosing range check", g.iv.Name(), g.prefix, g.count)
}
