package frontend

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"strings"
)

// Lowering of records.
//
//	if p := M.Lookup(k); p != nil { … p.F … p.Arr[3] … }  →  ref.field.load %borrow "f" / "arr[3]"
//	p.F = e / p.F += e / p.F++                            →  (ref.field.load → arith →) ref.field.store — **not atomic**
//	M.Update(k, T{F: e, …})                               →  record.make [every leaf] (omitted leaves are an explicit 0) → map.update
//
// A record value itself (`*p`, variables, arguments, return values) is outside the subset — stopped with a position. Indexes are constants only (a variable index is ref.index — a later plan).

// recordRef is the layout when the checked reference is a record borrow (nil for an integer map).
func (c *checkedRef) record() *SharedABI { return c.rec }

// fieldPath returns the path and type if e is a leaf of a checked record reference (`p.F`, `p.Arr[c]`, nested `p.A.B`, `p.Arr[c].F`, `p.M[c][d]`).
// If handled is false, e is not a record field shape (left to the caller's other branches). If handled and ok is false, it has already reported.
// dynField takes variable indexes first — a variable index reaching here has no proof (GB006).
// c is the checked borrow at the leaf's root (outer or inner).
func (l *lowerer) fieldPath(e ast.Expr) (c *checkedRef, path string, t IntType, ok, handled bool) {
	acc, ok, handled := l.leafAccess(e, true)
	if !handled || !ok {
		return nil, "", IntType{}, ok, handled
	}
	if len(acc.vars) > 0 {
		v := acc.vars[0]
		x := types.ExprString(v.arr)
		l.fail(Rejected, GB006NonConstant, v.e.Pos(), "the index of %s must be a constant, or a uint32 variable checked by `if i < uint32(len(%s)) { … }`, or the counter of an enclosing loop of at most len(%s) iterations", x, x, x)
		return nil, "", IntType{}, false, true
	}
	return acc.ref, acc.path, *acc.end.Int, true, true
}

// borrowType returns the type text of the record borrow c.
func borrowType(c *checkedRef) string { return fmt.Sprintf("!ebpf.borrowed<%s>", c.rec.mlir()) }

// fieldLoad reads the value of a leaf of borrow c.
func (l *lowerer) fieldLoad(c *checkedRef, path string, t IntType) value {
	r := l.val()
	l.emit("%s = ebpf.ref.field.load %s %q : %s -> %s", r, c.borrow, path, borrowType(c), t.mlir())
	return value{r, vtypeOf(t)}
}

func (l *lowerer) fieldStore(c *checkedRef, path string, v value) {
	l.emit("ebpf.ref.field.store %s %q, %s : %s, %s", c.borrow, path, v.name, borrowType(c), v.t.mlir())
}

// fieldAssign handles `p.F = e` and `p.F op= e` (one left-hand side). If handled is false the left-hand side is not a field.
func (l *lowerer) fieldAssign(s *ast.AssignStmt) (handled bool) {
	fieldLHS := -1
	for i, lhs := range s.Lhs {
		if _, _, _, h := l.peekField(lhs); h {
			fieldLHS = i
		}
	}
	if fieldLHS < 0 {
		return false
	}
	if len(s.Lhs) != 1 || len(s.Rhs) != 1 {
		l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "a record field may only be assigned alone (`p.F = e` / `p.F op= e`)")
		return true
	}
	if d, dok, dh := l.dynField(s.Lhs[0]); dh {
		if !dok {
			return true
		}
		t := vtypeOf(d.elemT)
		var v value
		var ok bool
		if s.Tok == token.ASSIGN {
			if v, ok = l.expr(s.Rhs[0], &t); !ok {
				return true
			}
		} else {
			op, known := assignOps[s.Tok]
			if !known {
				l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
				return true
			}
			cur := l.dynLoad(d)
			if v, ok = l.binary(s.Pos(), op, cur, s.Rhs[0], t); !ok {
				return true
			}
		}
		l.dynStore(d, v)
		return true
	}
	c, path, it, ok, _ := l.fieldPath(s.Lhs[0])
	if !ok {
		return true
	}
	t := vtypeOf(it)
	var v value
	switch s.Tok {
	case token.ASSIGN:
		if v, ok = l.expr(s.Rhs[0], &t); !ok {
			return true
		}
	default:
		op, known := assignOps[s.Tok]
		if !known {
			l.fail(Unknown, GB001UnsupportedConstruct, s.Pos(), "assignment %s is not supported", s.Tok)
			return true
		}
		// load → arithmetic → store (not atomic — see the bpf.Array doc).
		cur := l.fieldLoad(c, path, it)
		if v, ok = l.binary(s.Pos(), op, cur, s.Rhs[0], t); !ok {
			return true
		}
	}
	l.fieldStore(c, path, v)
	return true
}

// peekField reports, without reporting errors, whether e has a record field shape (a check before calling fieldPath).
func (l *lowerer) peekField(e ast.Expr) (string, IntType, bool, bool) {
	id, steps := recordChain(e) // also nested chains (p.A.B, p.Arr[i].F)
	if id == nil || len(steps) == 0 {
		return "", IntType{}, false, false
	}
	if _, ok := steps[0].(*ast.SelectorExpr); !ok {
		return "", IntType{}, false, false
	}
	pv, _ := l.a.info.Uses[id].(*types.Var)
	if pv == nil || l.localVar(id, false) == nil {
		return "", IntType{}, false, false
	}
	_, isPtr := pv.Type().(*types.Pointer)
	return "", IntType{}, false, isPtr
}

// fieldIncDec lowers `p.F++` / `p.F--`.
func (l *lowerer) fieldIncDec(s *ast.IncDecStmt) (handled bool) {
	if _, _, _, h := l.peekField(s.X); !h {
		return false
	}
	if d, dok, dh := l.dynField(s.X); dh {
		if dok {
			cur := l.dynLoad(d)
			one := l.constant(constant.MakeInt64(1), cur.t)
			op := "arith.addi"
			if s.Tok == token.DEC {
				op = "arith.subi"
			}
			r := l.val()
			l.emit("%s = %s %s, %s : %s", r, op, cur.name, one.name, cur.t.mlir())
			l.dynStore(d, value{r, cur.t})
		}
		return true
	}
	c, path, it, ok, _ := l.fieldPath(s.X)
	if !ok {
		return true
	}
	cur := l.fieldLoad(c, path, it)
	one := l.constant(constant.MakeInt64(1), cur.t)
	op := "arith.addi"
	if s.Tok == token.DEC {
		op = "arith.subi"
	}
	r := l.val()
	l.emit("%s = %s %s, %s : %s", r, op, cur.name, one.name, cur.t.mlir())
	l.fieldStore(c, path, value{r, cur.t})
	return true
}

// recordMake lowers a record composite literal to record.make (omitted leaves are Go's zero value — an explicit 0).
func (l *lowerer) recordMake(e ast.Expr, rec SharedABI) (string, bool) {
	defer l.at(e.Pos())()
	if sp := rec.Record.Special; sp != nil {
		// a record value with a lock / timer cannot be made (bpf-mlir refuses record.make of a record with a lock — a timer is also a kernel object, so copying its value is meaningless).
		l.fail(Rejected, GB016SharedABIShape, e.Pos(), "record %s holds %s %s — its value cannot be written as a literal (Update / Output); write its other fields through `if p := M.Lookup(k); p != nil { p.F = … }`", rec.Record.Symbol, specialName(sp.Type.Kind), sp.GoName)
		return "", false
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok || !types.Identical(l.a.info.Types[e].Type, rec.GoType) {
		l.fail(Unknown, GB001UnsupportedConstruct, e.Pos(), "a record value must be written as a composite literal %s{…} here (record values in variables, parameters and results are outside the subset)", rec.Record.Symbol)
		return "", false
	}
	given := map[string]ast.Expr{} // Go field name → expression
	for _, el := range cl.Elts {
		kv, isKV := el.(*ast.KeyValueExpr)
		if !isKV {
			l.fail(Unknown, GB001UnsupportedConstruct, el.Pos(), "a record literal must name its fields (%s{F: e, …})", rec.Record.Symbol)
			return "", false
		}
		given[kv.Key.(*ast.Ident).Name] = kv.Value
	}
	var paths, names, typs []string
	zeros := map[IntType]value{}
	zero := func(t IntType) value {
		if z, ok := zeros[t]; ok {
			return z
		}
		z := l.constant(constant.MakeInt64(0), vtypeOf(t))
		zeros[t] = z
		return z
	}
	add := func(path string, v value) {
		paths = append(paths, fmt.Sprintf("%q", path))
		names = append(names, v.name)
		typs = append(typs, v.t.mlir())
	}
	for _, f := range rec.Record.Fields {
		fe, has := given[f.GoName]
		if nestedShape(f.Type) {
			// nested records, record arrays, 2-dimensional arrays — flattened to leaf paths (omitted leaves are Go's zero value — an explicit 0).
			var sub ast.Expr
			if has {
				sub = fe
			}
			if !l.makeLeaves(f.Name, f.Type, sub, add, zero) {
				return "", false
			}
			continue
		}
		switch f.Type.Kind {
		case ABIInt:
			if !has {
				add(f.Name, zero(*f.Type.Int))
				continue
			}
			t := vtypeOf(*f.Type.Int)
			v, ok := l.expr(fe, &t)
			if !ok {
				return "", false
			}
			add(f.Name, v)
		case ABIArray:
			elemT := *f.Type.Array.Elem.Int
			if call, isCall := fe.(*ast.CallExpr); has && isCall && l.taskOp(call) == "current_comm" {
				// bpf.CurrentComm(): 0 in record.make; Output writes the reserved field with task.comm after store_record.
				if !l.commOK || elemT.Bits != 8 {
					l.fail(Rejected, GB001UnsupportedConstruct, fe.Pos(), "bpf.CurrentComm() may only be the value of a [16]uint8 field in a ring buffer event literal (`Events.Output(Ev{Comm: bpf.CurrentComm()})` — the name is written into the reserved event)")
					return "", false
				}
				l.commPaths = append(l.commPaths, f.Name)
				for i := uint64(0); i < f.Type.Array.Count; i++ {
					add(indexPath(f.Name, i), zero(elemT))
				}
				continue
			}
			var elts []ast.Expr
			if has {
				acl, isCL := fe.(*ast.CompositeLit)
				if !isCL {
					l.fail(Unknown, GB001UnsupportedConstruct, fe.Pos(), "the array field %s must be given as an array literal ([N]T{…}) in a record literal", f.GoName)
					return "", false
				}
				for _, el := range acl.Elts {
					if _, isKV := el.(*ast.KeyValueExpr); isKV {
						l.fail(Unknown, GB001UnsupportedConstruct, el.Pos(), "indexed elements in an array literal are not supported; list the elements in order")
						return "", false
					}
				}
				elts = acl.Elts
			}
			for i := uint64(0); i < f.Type.Array.Count; i++ {
				if i < uint64(len(elts)) {
					t := vtypeOf(elemT)
					v, ok := l.expr(elts[i], &t)
					if !ok {
						return "", false
					}
					add(indexPath(f.Name, i), v)
				} else {
					add(indexPath(f.Name, i), zero(elemT))
				}
			}
		}
	}
	r := l.val()
	l.emit("%s = ebpf.record.make [%s] (%s) : (%s) -> %s", r, strings.Join(paths, ", "), strings.Join(names, ", "), strings.Join(typs, ", "), rec.mlir())
	return r, true
}

// recordLiteralArgs returns the composite literals the capability check does not treat as heap allocations (records in map value argument positions).
// Record literals of AtomicAdd are included too — lowering names "AtomicAdd takes integers only" with GB016 (not stopped earlier by go.heap).
func (a *analyzer) recordLiteralArgs(body ast.Node) map[*ast.CompositeLit]bool {
	out := map[*ast.CompositeLit]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		e, known := lookupAPI(a.info.Uses[sel.Sel])
		_, isStatus := statusOps[e.op]
		if known && e.op == "lpm_lookup" {
			// the address `[4]byte{…}` of LPMTrie4.Lookup (the addr leaves of record.make).
			for _, arg := range call.Args {
				if cl, ok := arg.(*ast.CompositeLit); ok {
					out[cl] = true
				}
			}
			return true
		}
		if !known || !(e.op == "update" || e.op == "atomic_add" || e.op == "output" || e.op == "output_str" || e.op == "output_str_discard" || e.op == "output_kernel_str" || e.op == "output_buf" || e.op == "perf_output" || e.op == "lookup" || e.op == "seq_write" || e.op == "sys_bpf" || isStatus) { // including seq_write and sys_bpf
			return true
		}
		// the key / value / event position of a map operation (including record keys).
		for _, arg := range call.Args {
			cl, ok := arg.(*ast.CompositeLit)
			if !ok {
				continue
			}
			a.markRecordLiteral(cl, out)
		}
		return true
	})
	// a whole-record assignment `*e = V{…}` to a reserved event (e is the variable of `if e, ok := M.Reserve(); ok` — lowering makes it store_record).
	resvVars := map[*types.Var]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		if s, ok := n.(*ast.IfStmt); ok {
			if as, ok := s.Init.(*ast.AssignStmt); ok && len(as.Lhs) == 2 && len(as.Rhs) == 1 {
				if call, ok := ast.Unparen(as.Rhs[0]).(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if e, known := lookupAPI(a.info.Uses[sel.Sel]); known && e.op == "ringbuf_reserve" {
							if id, ok := as.Lhs[0].(*ast.Ident); ok {
								if v, ok := a.info.Defs[id].(*types.Var); ok {
									resvVars[v] = true
								}
							}
						}
					}
				}
			}
		}
		return true
	})
	ast.Inspect(body, func(n ast.Node) bool {
		as, ok := n.(*ast.AssignStmt)
		if !ok || len(as.Lhs) != 1 || len(as.Rhs) != 1 {
			return true
		}
		star, ok := ast.Unparen(as.Lhs[0]).(*ast.StarExpr)
		if !ok {
			return true
		}
		id, ok := ast.Unparen(star.X).(*ast.Ident)
		if !ok {
			return true
		}
		if v, ok := a.info.Uses[id].(*types.Var); ok && resvVars[v] {
			if cl, ok := ast.Unparen(as.Rhs[0]).(*ast.CompositeLit); ok {
				a.markRecordLiteral(cl, out)
			}
		}
		return true
	})
	return out
}

// markRecordLiteral puts a record composite literal (and the array literals in it) into out.
func (a *analyzer) markRecordLiteral(cl *ast.CompositeLit, out map[*ast.CompositeLit]bool) {
	if n, isNamed := a.info.Types[cl].Type.(*types.Named); isNamed {
		if _, isStruct := n.Underlying().(*types.Struct); isStruct {
			out[cl] = true
			markNestedLiterals(cl, out)
		}
	}
}

// markNestedLiterals recursively puts the array literals and nested record literals in a record literal (including `{…}` with the element type omitted) into out
// (leaves of record.make — not heap allocations).
func markNestedLiterals(cl *ast.CompositeLit, out map[*ast.CompositeLit]bool) {
	for _, el := range cl.Elts {
		if kv, ok := el.(*ast.KeyValueExpr); ok {
			el = kv.Value
		}
		if acl, ok := ast.Unparen(el).(*ast.CompositeLit); ok {
			out[acl] = true
			markNestedLiterals(acl, out)
		}
	}
}

// recordMapCall lowers a statement on a map with record values (Update). AtomicAdd takes integers only (bpf-mlir's map.atomic_add).
func (l *lowerer) recordMapCall(call *ast.CallExpr, m *BpfMap, e apiEntry, name string) {
	switch e.op {
	case "atomic_add":
		l.fail(Rejected, GB016SharedABIShape, call.Pos(), "%s.AtomicAdd needs an integer value, but %s holds the record %s — count with an integer map's AtomicAdd (a record field's += is not atomic)", m.Symbol, m.Symbol, m.Value.Record.Symbol)
		return
	case "update":
	default:
		l.fail(Unknown, GB002UnsupportedCall, call.Pos(), "%s.%s has no lowering for a record value", m.Symbol, name)
		return
	}
	k, ok := l.mapKey(m, call.Args[0])
	if !ok {
		return
	}
	v, ok := l.recordMake(call.Args[1], m.Value)
	if !ok {
		return
	}
	defer l.at(call.Pos())()
	l.emit("ebpf.map.update %s[%s], %s : %s, %s, %s", l.mapArgs[m], k, v, l.mapType(m), m.Key.mlir(), m.Value.mlir())
}

// badVarType reports that a local variable's type is outside the subset. A record type is named with GB016 (a record value in a variable is outside the subset).
func (l *lowerer) badVarType(p token.Pos, name string, t types.Type) {
	if r, ok := l.a.recordBySymbol[typeName(t)]; ok && r.GoType != nil && types.Identical(r.GoType, t) {
		l.fail(Rejected, GB016SharedABIShape, p, "variable %s holds the record %s — record values in variables, parameters and results are outside the subset; read and write its fields through the Lookup pointer (p.F)", name, typeName(t))
		return
	}
	if l.prog != nil && l.prog.tpEvent != nil {
		if pt, ok := t.(*types.Pointer); ok && types.Identical(pt.Elem(), l.prog.tpEvent) { // ctx.Event() held in a variable
			l.fail(Rejected, GB008ProgramShape, p, "variable %s holds ctx.Event() — the event record is not a value; read a tagged field in place: ctx.Event().F (each read is one tracepoint field load)", name)
			return
		}
	}
	if _, isRef := l.a.mapValuePointee(t); isRef { // a Lookup result held in a variable — say how to fix it
		l.fail(Rejected, GB005NilCheckShape, p, "variable %s holds a pointer to a map value (%s) — the result of M.Lookup(k) may be nil and is read only inside `if %s := M.Lookup(k); %s != nil { … }` (it cannot be kept in a variable)", name, t, name, name)
		return
	}
	l.fail(Unknown, GB001UnsupportedConstruct, p, "variable %s has type %s, which is not in the supported subset (integers and bool)", name, t)
}

func typeName(t types.Type) string {
	if n, ok := t.(*types.Named); ok {
		return n.Obj().Name()
	}
	return ""
}

// isFieldAtomicAdd reports whether call is `bpf.AtomicAdd(…)` (including explicit type arguments `bpf.AtomicAdd[uint64](…)`).
func (l *lowerer) isFieldAtomicAdd(call *ast.CallExpr) bool {
	fun := ast.Unparen(call.Fun)
	switch f := fun.(type) {
	case *ast.IndexExpr:
		fun = f.X
	case *ast.IndexListExpr:
		fun = f.X
	}
	sel, ok := fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj := l.a.info.Uses[sel.Sel]
	if obj == nil || !inAPIPackage(obj) {
		return false
	}
	e, known := lookupAPI(obj)
	return known && e.op == "field_atomic_add"
}

// fieldAtomicAdd lowers `bpf.AtomicAdd(&p.F, d)` (a statement) to ebpf.ref.field.atomic_add.
// The accepted shape is a 32 / 64 bit integer field directly under a checked record pointer whose offset is a multiple of its width (natural alignment — bpf-mlir
// also stops it in ebpf-verify-records, but the frontend stops it first at the Go position). Anything else is GB021 (AtomicShape — the declaration is valid, the use is restricted:
// make the field 32 / 64 bit at a natural position, or count in an integer map).
func (l *lowerer) fieldAtomicAdd(call *ast.CallExpr) {
	const how = "bpf.AtomicAdd takes &p.F — a 32 / 64-bit integer field of a checked record pointer p (`if p := M.Lookup(k); p != nil { bpf.AtomicAdd(&p.F, d) }`)"
	if len(call.Args) != 2 {
		l.fail(Rejected, GB021AtomicShape, call.Pos(), "%s", how)
		return
	}
	u, isAddr := ast.Unparen(call.Args[0]).(*ast.UnaryExpr)
	if id, isID := ast.Unparen(call.Args[0]).(*ast.Ident); isID && func() bool {
		uv, _ := l.a.info.Uses[id].(*types.Var)
		c := l.borrowOf(uv)
		return c != nil && c.record() == nil
	}() {
		l.fail(Rejected, GB021AtomicShape, id.Pos(), "%s points to the integer value of a map — add to it with the map's own method (`M.AtomicAdd(k, d)`); bpf.AtomicAdd is for a field of a record (&p.F)", id.Name)
		return
	}
	if !isAddr || u.Op != token.AND {
		l.fail(Rejected, GB021AtomicShape, call.Args[0].Pos(), "the first argument is not &p.F — %s", how)
		return
	}
	target := ast.Unparen(u.X)
	if ix, isIx := target.(*ast.IndexExpr); isIx {
		l.fail(Rejected, GB021AtomicShape, ix.Pos(), "bpf.AtomicAdd cannot add to an array element (bpf-mlir has no atomic add on an element) — use a scalar field, or count in an integer map with M.AtomicAdd(k, d)")
		return
	}
	sel, isSel := target.(*ast.SelectorExpr)
	if _, _, _, h := l.peekField(target); !isSel || !h {
		l.fail(Rejected, GB021AtomicShape, u.X.Pos(), "the operand of & is not a field of a checked record pointer — %s", how)
		return
	}
	// also nested leaves (&p.A.N, &p.Arr[2].N) — offset is the absolute offset from the start of the record. Leaves with a variable index are not accepted (the path is constant).
	if acc, aok, _ := l.walkAccess(target, false); aok && len(acc.vars) > 0 {
		l.fail(Rejected, GB021AtomicShape, acc.vars[0].e.Pos(), "bpf.AtomicAdd needs a constant field path — the index of %s is not a constant (use a constant index, or count in an integer map with M.AtomicAdd(k, d))", types.ExprString(acc.vars[0].arr))
		return
	}
	c, path, it, ok, _ := l.fieldPath(target)
	if !ok {
		return
	}
	acc, _, _ := l.walkAccess(target, false)
	if it.Bits != 32 && it.Bits != 64 {
		l.fail(Rejected, GB021AtomicShape, sel.Pos(), "field %s is %d bits — bpf.AtomicAdd needs a 32 or 64-bit field (bpf-mlir's atomic add widths)", path, it.Bits)
		return
	}
	if w := uint64(it.Bits / 8); acc.offset%w != 0 {
		l.fail(Rejected, GB021AtomicShape, sel.Pos(), "field %s of record %s is at offset %d, not a multiple of its width (%d bytes) — an atomic add needs a naturally aligned field; move the field (explicit `_` padding before it) or count in an integer map", path, c.rec.Record.Symbol, acc.offset, w)
		return
	}
	// A delta that reads a field of the same checked borrow (`bpf.AtomicAdd(&p.F, p.G)`) lets another CPU's update land between the read and the add — it looks
	// atomic but is a read-modify-write (the same loophole as mojo-bpf-mlir's MB017). Values from another map, constants, packets and locals are accepted
	// (a field of the other borrow is a different value: a different map, or a different constant key of the same map).
	var sameRef ast.Expr
	ast.Inspect(call.Args[1], func(n ast.Node) bool {
		if s, isSel := n.(*ast.SelectorExpr); isSel && sameRef == nil {
			if id, isID := ast.Unparen(s.X).(*ast.Ident); isID && l.a.info.Uses[id] == c.obj {
				sameRef = s
			}
		}
		return sameRef == nil
	})
	if sameRef != nil {
		l.fail(Rejected, GB021AtomicShape, sameRef.Pos(), "the delta of bpf.AtomicAdd reads a field of the same record (%s) — the read and the add are not one atomic step (another CPU can update the record in between); use a delta from a constant, another map, the packet or a local value", types.ExprString(sameRef))
		return
	}
	// A read of a field of the same borrow through a local variable (`v := p.G; bpf.AtomicAdd(&p.N, v)`): follows the assignments in the function body
	// and marks variables whose right-hand side reads a field of the same borrow (or a local carrying one) (flow-insensitive — marked if any assignment carries it).
	if v := l.borrowedFieldCarrier(c, call.Args[1]); v != nil {
		l.fail(Rejected, GB021AtomicShape, v.Pos(), "the delta of bpf.AtomicAdd reads a field of the same record through the local variable %s — the read and the add are not one atomic step (another CPU can update the record in between); use a delta from a constant, another map, the packet or a value not read from this record", v.Name)
		return
	}
	t := vtypeOf(it)
	d, ok := l.expr(call.Args[1], &t)
	if !ok {
		return
	}
	defer l.at(call.Pos())()
	l.emit("ebpf.ref.field.atomic_add %s %q, %s : %s, %s", c.borrow, path, d.name, borrowType(c), t.mlir())
}

// borrowedFieldCarrier returns a local variable in the delta expression that carries a field read of the checked borrow c (the borrow being added to), or nil.
// It follows every assignment in the function body (:= / = / op= / var) to a fixed point — flow-insensitive and conservative (if one assignment carries it, a use after another assignment also stops).
func (l *lowerer) borrowedFieldCarrier(c *checkedRef, delta ast.Expr) *ast.Ident {
	if c == nil || l.fnBody == nil {
		return nil
	}
	borrow := c.obj
	carries := map[*types.Var]bool{}
	reads := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				if id, ok := ast.Unparen(x.X).(*ast.Ident); ok && l.a.info.Uses[id] == borrow {
					found = true
				}
			case *ast.Ident:
				if v, ok := l.a.info.Uses[x].(*types.Var); ok && carries[v] {
					found = true
				}
			}
			return !found
		})
		return found
	}
	mark := func(lhs ast.Expr, rhs ast.Expr) bool {
		id, ok := ast.Unparen(lhs).(*ast.Ident)
		if !ok || id.Name == "_" || !reads(rhs) {
			return false
		}
		v, _ := l.a.info.Defs[id].(*types.Var)
		if v == nil {
			v, _ = l.a.info.Uses[id].(*types.Var)
		}
		if v == nil || v == borrow || carries[v] {
			return false
		}
		carries[v] = true
		return true
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(l.fnBody, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.AssignStmt:
				if len(s.Lhs) == len(s.Rhs) {
					for i := range s.Lhs {
						if mark(s.Lhs[i], s.Rhs[i]) {
							changed = true
						}
					}
				}
			case *ast.ValueSpec:
				if len(s.Names) == len(s.Values) {
					for i := range s.Names {
						if mark(s.Names[i], s.Values[i]) {
							changed = true
						}
					}
				}
			}
			return true
		})
	}
	var hit *ast.Ident
	ast.Inspect(delta, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && hit == nil {
			if v, ok := l.a.info.Uses[id].(*types.Var); ok && carries[v] {
				hit = id
			}
		}
		return hit == nil
	})
	return hit
}
