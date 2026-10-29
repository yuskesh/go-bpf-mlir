package frontend

import (
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
)

// Range proofs for variable Array keys.
//
// Array Update / AtomicAdd silently do nothing when a variable key is out of range (≥ MaxEntries) (Lookup returns nil). If the frontend can prove the key's upper bound
// from the source shape it says nothing (a proof comment in the generated .mlir); if it cannot, it does not stop but emits a **Conditional** diagnostic (GB020)
// (a review point — never silent, and existing examples still generate as Conditional).
//
// Bounds are per SSA value name (l.bounds — SSA names are unique, so bounds do not leak between if arms or past a merge). Shapes with a known bound:
//   constants, `x & C`, `x % C` (unsigned), `x >> C`, sums of bounded values, widening conversions, loop variables (count − 1),
//   an immediately following clamp `if k >= C { k = D }` / `if k > C { k = D }` (D constant).

// exprBound returns the (inclusive) upper bound of the expression's value (false if unknown). Unsigned integer expressions only.
func (l *lowerer) exprBound(e ast.Expr) (uint64, bool) {
	tv := l.a.info.Types[e]
	if tv.Value != nil {
		if constant.Sign(constant.ToInt(tv.Value)) < 0 {
			return 0, false
		}
		v, exact := constant.Uint64Val(constant.ToInt(tv.Value))
		return v, exact
	}
	if !isUnsignedInt(tv.Type) {
		return 0, false
	}
	switch e := e.(type) {
	case *ast.ParenExpr:
		return l.exprBound(e.X)
	case *ast.Ident:
		v := l.localVar(e, false)
		if v == nil {
			return 0, false
		}
		val, ok := l.env[v]
		if !ok {
			return 0, false
		}
		b, ok := l.bounds[val.name]
		return b, ok
	case *ast.CallExpr:
		if l.a.info.Types[e.Fun].IsType() && len(e.Args) == 1 && isUnsignedInt(l.a.info.Types[e.Args[0]].Type) {
			b, ok := l.exprBound(e.Args[0])
			if ok && b <= maxOf(tv.Type) {
				return b, true
			}
		}
	case *ast.BinaryExpr:
		x, okx := l.exprBound(e.X)
		y, oky := l.exprBound(e.Y)
		yConst := l.a.info.Types[e.Y].Value != nil
		switch e.Op {
		case token.AND:
			switch {
			case okx && oky:
				return min(x, y), true
			case okx:
				return x, true
			case oky:
				return y, true
			}
		case token.REM:
			if yConst && oky && y > 0 {
				if okx {
					return min(x, y-1), true
				}
				return y - 1, true
			}
		case token.SHR:
			if !okx {
				x = maxOf(tv.Type) // a value with no known bound is still bounded by its type's maximum
			}
			if yConst && oky && y < 64 {
				return x >> y, true
			}
		case token.ADD:
			if okx && oky && x <= maxOf(tv.Type)-y {
				return x + y, true
			}
		}
	}
	return 0, false
}

func isUnsignedInt(t types.Type) bool {
	if t == nil {
		return false
	}
	b, ok := t.Underlying().(*types.Basic)
	return ok && b.Info()&types.IsUnsigned != 0 && b.Info()&types.IsInteger != 0
}

func maxOf(t types.Type) uint64 {
	switch amd64Sizes.Sizeof(t) {
	case 1:
		return 1<<8 - 1
	case 2:
		return 1<<16 - 1
	case 4:
		return 1<<32 - 1
	}
	return 1<<64 - 1
}

// noteBound records the upper bound of v, the lowered value of e (an assignment's right-hand side or a declaration's initial value).
func (l *lowerer) noteBound(e ast.Expr, v value) {
	if b, ok := l.exprBound(e); ok {
		l.bounds[v.name] = b
	}
}

// clampAfterIf records the upper bound of k right after `if k >= C { k = D }` / `if k > C { k = D }` (no else, D constant).
func (l *lowerer) clampAfterIf(s *ast.IfStmt) {
	if s.Init != nil || s.Else != nil || len(s.Body.List) != 1 {
		return
	}
	be, ok := s.Cond.(*ast.BinaryExpr)
	if !ok || (be.Op != token.GEQ && be.Op != token.GTR) {
		return
	}
	kid, _ := be.X.(*ast.Ident)
	ctv := l.a.info.Types[be.Y]
	as, _ := s.Body.List[0].(*ast.AssignStmt)
	if kid == nil || ctv.Value == nil || as == nil || as.Tok != token.ASSIGN || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
		return
	}
	k := l.localVar(kid, false)
	if lid, _ := as.Lhs[0].(*ast.Ident); k == nil || lid == nil || l.a.info.Uses[lid] != k || !isUnsignedInt(k.Type()) {
		return
	}
	dtv := l.a.info.Types[as.Rhs[0]]
	if dtv.Value == nil {
		return
	}
	c, exact1 := constant.Uint64Val(constant.ToInt(ctv.Value))
	d, exact2 := constant.Uint64Val(constant.ToInt(dtv.Value))
	if !exact1 || !exact2 || (be.Op == token.GEQ && c == 0) {
		return
	}
	bound := c // the else of k > C is k ≤ C
	if be.Op == token.GEQ {
		bound = c - 1 // the else of k >= C is k ≤ C − 1
	}
	if val, ok := l.env[k]; ok {
		l.bounds[val.name] = max(bound, d)
	}
}

// proveArrayKey checks whether the variable Array key e is below MaxEntries, and emits a comment into the .mlir if it can prove it, or else
// a Conditional diagnostic (GB020).
func (l *lowerer) proveArrayKey(m *BpfMap, e ast.Expr) {
	if b, ok := l.exprBound(e); ok && b < m.MaxEntries {
		l.b.WriteString(l.indent + "// key proven < MaxEntries " + uitoa(m.MaxEntries) + " of " + m.Symbol + ": at most " + uitoa(b) + " (checked by the frontend)\n")
		return
	}
	l.a.report(Conditional, GB020ArrayKeyUnproven, e.Pos(), l.path(),
		"the key of map %s is not proven < MaxEntries (%d) — an out-of-range key makes Update / AtomicAdd do nothing and Lookup give nil (silently); clamp it (`if k >= %d { k = %d }`) or mask it (`k & …`) to prove it",
		m.Symbol, m.MaxEntries, m.MaxEntries, m.MaxEntries-1)
}
