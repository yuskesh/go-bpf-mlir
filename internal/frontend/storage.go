package frontend

import (
	"go/ast"
	"go/types"
)

// Local storage maps (bpf-mlir's storage.get / storage.delete):
//
//	var Seen = bpf.TaskStorage[Ev]{}
//	if v := Seen.Get(child, bpf.Create); v != nil { … }   → %m = ebpf.storage.get %Seen, %child create : !ebpf.map<"task_storage", i32, V>, !ebpf.kptr<"task_struct"> -> !ebpf.maybe_ref<V>
//	                                                          ebpf.ref.check %m present(%b) { … } absent { … }   (the same borrow rules as the if of Lookup)
//	st := Seen.Delete(child)                               → %st = ebpf.storage.delete %Seen, %child : … -> i64
//
// The owner is a pointer variable of a kernel local type (the checked p of TPArg / FentryArg, or the m of a kfield.ptr walk), and the kernel struct name of that local type
// must be the struct of the map's kind (storageOwnerStruct — the same table as bpf-mlir's Support/LocalStorage.h).

// storageKinds maps a bpf type name to (schema kind, the owner's kernel struct).
var storageKinds = map[string][2]string{
	"TaskStorage":  {"task_storage", "task_struct"},
	"SKStorage":    {"sk_storage", "sock"},
	"CgrpStorage":  {"cgrp_storage", "cgroup"},
	"InodeStorage": {"inode_storage", "inode"},
}

// storageOwnerStruct is the owner's kernel struct for a map kind.
func storageOwnerStruct(kind string) string {
	for _, k := range storageKinds {
		if k[0] == kind {
			return k[1]
		}
	}
	return ""
}

// storageInstance returns the kind and V if t is an instance of a bpf local storage map.
func storageInstance(t types.Type) (kind string, v types.Type, ok bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg {
		return "", nil, false
	}
	k, known := storageKinds[n.Origin().Obj().Name()]
	if !known || n.TypeArgs().Len() != 1 {
		return "", nil, false
	}
	return k[0], n.TypeArgs().At(0), true
}

// collectStorage checks and collects local storage map declarations (key i32 — the owner's fd, max_entries 0, flags BPF_F_NO_PREALLOC).
func (a *analyzer) collectStorage(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, kind string, v types.Type) {
	m := &BpfMap{Symbol: obj.Name(), Kind: kind, Flags: lpmNoPrealloc, Pos: a.position(name.Pos()), obj: obj}
	if vi, okV := intTypeOf(v); okV {
		if vi.Bits < 32 {
			a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "map %s: an integer value must be 32 or 64 bit, got %s (wrap narrower values in a record)", obj.Name(), v)
			return
		}
		m.Value = sharedABIOfInt(v, vi)
	} else if rv, okR := a.recordOf(v, name.Pos(), "map "+obj.Name()+" value"); okR {
		m.Value = rv
	} else {
		return
	}
	if len(vs.Values) == len(vs.Names) {
		cl, ok := vs.Values[i].(*ast.CompositeLit)
		if !ok || len(cl.Elts) != 0 {
			a.report(Rejected, GB009MapDeclShape, vs.Values[i].Pos(), nil, "map %s: a local storage map is declared as `bpf.%s[V]{}` (it has no key and no MaxEntries — the kernel object is the key)", obj.Name(), obj.Type().(*types.Named).Origin().Obj().Name())
			return
		}
	}
	m.Key = sharedABIOfInt(types.Typ[types.Int32], IntType{32, true})
	a.maps = append(a.maps, m)
	a.mapByObj[obj] = m
}

// storageOwner returns the value name and kernel struct of the owner argument of Get / Delete (a pointer variable of a kernel local type whose struct matches the kind).
func (l *lowerer) storageOwner(m *BpfMap, call *ast.CallExpr, method string) (string, string, bool) {
	want := storageOwnerStruct(m.Kind)
	arg := ast.Unparen(call.Args[0])
	id, _ := arg.(*ast.Ident)
	var kp kptrVal
	isK := false
	if id != nil {
		if v, _ := l.a.info.Uses[id].(*types.Var); v != nil {
			kp, isK = l.kptrs[v]
		}
	}
	if !isK {
		l.fail(Rejected, GB027KernelTypeShape, arg.Pos(), "the owner of %s.%s must be a checked kernel pointer variable (`p` of `if p := bpf.FentryArg[T](ctx, i); p != nil`, `p := bpf.TPArg[T](ctx, i)`, or `if m := p.F; m != nil`) whose type is the kernel struct %s", m.Symbol, method, want)
		return "", "", false
	}
	if kp.kt.Name != want {
		l.fail(Rejected, GB027KernelTypeShape, arg.Pos(), "the owner of %s.%s is a pointer to the kernel struct %s (%s), but a %s map is keyed by %s", m.Symbol, method, kp.kt.Name, kp.kt.goName(), m.Kind, want)
		return "", "", false
	}
	if len(l.loops) > 0 {
		l.fail(Rejected, GB008ProgramShape, call.Pos(), "%s.%s may not be called inside a loop (bpf-mlir keeps storage.get / storage.delete out of loop bodies)", m.Symbol, method)
		return "", "", false
	}
	return kp.name, want, true
}

// emitStorageGet emits the ebpf.storage.get of `S.Get(owner, flag)` and returns the name of the maybe_ref value.
func (l *lowerer) emitStorageGet(m *BpfMap, call *ast.CallExpr) (string, bool) {
	owner, st, ok := l.storageOwner(m, call, "Get")
	if !ok {
		return "", false
	}
	tv := l.a.info.Types[call.Args[1]]
	if tv.Value == nil {
		l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the second argument of %s.Get must be the constant bpf.Create or bpf.NoCreate", m.Symbol)
		return "", false
	}
	create := ""
	if n, _ := constUint64(tv); n == 1 {
		create = " create"
	} else if n != 0 {
		l.fail(Rejected, GB006NonConstant, call.Args[1].Pos(), "the second argument of %s.Get must be bpf.Create or bpf.NoCreate", m.Symbol)
		return "", false
	}
	defer l.at(call.Pos())()
	ref := l.val()
	l.emit("%s = ebpf.storage.get %s, %s%s : %s, !ebpf.kptr<%q> -> !ebpf.maybe_ref<%s>", ref, l.mapArgs[m], owner, create, l.mapType(m), st, m.Value.mlir())
	return ref, true
}

// storageDelete emits the ebpf.storage.delete of `S.Delete(owner)` (the raw i64 status).
func (l *lowerer) storageDelete(call *ast.CallExpr, m *BpfMap) (value, bool) {
	owner, st, ok := l.storageOwner(m, call, "Delete")
	if !ok {
		return value{}, false
	}
	defer l.at(call.Pos())()
	r := l.val()
	l.emit("%s = ebpf.storage.delete %s, %s : %s, !ebpf.kptr<%q> -> i64", r, l.mapArgs[m], owner, l.mapType(m), st)
	return value{r, vtype{bits: 64, signed: true}}, true
}

// isStorageOwnerArg reports whether call is a local storage Get / Delete and e is its first argument (an exception to the kernel pointer use check — checkKptrUses).
func (a *analyzer) isStorageOwnerArg(call *ast.CallExpr, e ast.Expr) bool {
	if len(call.Args) == 0 || call.Args[0] != e {
		return false
	}
	sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
	if !ok {
		return false
	}
	obj := a.info.Uses[sel.Sel]
	if obj == nil || !inAPIPackage(obj) {
		return false
	}
	en, known := lookupAPI(obj)
	return known && (en.op == "storage_get" || en.op == "storage_delete")
}
