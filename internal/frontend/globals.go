package frontend

import (
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"strings"
)

// Global variables (bpf-mlir's feature path F26):
//
//	var Port = bpf.Config[uint16]{}   → the schema's core.globals {name: Port, section: rodata}; on the eBPF side Port.Value() → ebpf.global.load @Port
//	var Seen = bpf.Global[uint64]{}   → {section: bss}; Seen.Add(d) → ebpf.global.atomic_add @Seen, d; Seen.Load() → ebpf.global.load @Seen
//
// The name is the ELF symbol and the schema global name (names shared with a map or program, and names starting with `_license` or `__ebpf`, are not allowed — bpf-mlir's schema).

// GlobalVar is a global variable declaration.
type GlobalVar struct {
	Symbol   string
	Section  string // "rodata" (Config) or "bss" (Global)
	Int      IntType
	Optional bool // Config's Optional (allows a Config that is never Set)
	Pos      token.Position
	obj      *types.Var
}

// PosString returns the position of the declaration.
func (g *GlobalVar) PosString() string { return posString(g.Pos) }

// globalInstance returns the section and T if t is an instance of bpf.Config[T] / bpf.Global[T].
func globalInstance(t types.Type) (section string, elem types.Type, ok bool) {
	n, isNamed := t.(*types.Named)
	if !isNamed || n.Origin().Obj().Pkg() == nil || n.Origin().Obj().Pkg().Path() != bpfPkg || n.TypeArgs() == nil || n.TypeArgs().Len() != 1 {
		return "", nil, false
	}
	switch n.Origin().Obj().Name() {
	case "Config":
		return "rodata", n.TypeArgs().At(0), true
	case "Global":
		return "bss", n.TypeArgs().At(0), true
	}
	return "", nil, false
}

// collectGlobal checks and collects a global variable declaration.
func (a *analyzer) collectGlobal(obj *types.Var, name *ast.Ident, vs *ast.ValueSpec, i int, section string, elem types.Type) {
	kind := map[string]string{"rodata": "Config", "bss": "Global"}[section]
	it, ok := intTypeOf(elem)
	if !ok {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "global %s: bpf.%s holds a fixed-width integer, got %s", obj.Name(), kind, elem)
		return
	}
	g := &GlobalVar{Symbol: obj.Name(), Section: section, Int: it, Pos: a.position(name.Pos()), obj: obj}
	if len(vs.Values) != len(vs.Names) {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "global %s needs an initializer bpf.%s[%s]{}", obj.Name(), kind, elem)
		return
	}
	cl, ok := vs.Values[i].(*ast.CompositeLit)
	if !ok {
		a.report(Rejected, GB009MapDeclShape, vs.Values[i].Pos(), nil, "global %s: the initializer must be a composite literal bpf.%s[%s]{…}", obj.Name(), kind, elem)
		return
	}
	for _, el := range cl.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		key, _ := kv.Key.(*ast.Ident)
		if !ok || key == nil || key.Name != "Optional" || section != "rodata" {
			a.report(Rejected, GB009MapDeclShape, el.Pos(), nil, "global %s: only the field Optional of bpf.Config may be set", obj.Name())
			return
		}
		tv := a.info.Types[kv.Value]
		if tv.Value == nil {
			a.report(Rejected, GB006NonConstant, kv.Value.Pos(), nil, "global %s: Optional must be a constant", obj.Name())
			return
		}
		g.Optional = tv.Value.ExactString() == "true"
	}
	if strings.HasPrefix(g.Symbol, "_license") || strings.HasPrefix(g.Symbol, "__ebpf") {
		a.report(Rejected, GB009MapDeclShape, name.Pos(), nil, "global %s: names starting with _license or __ebpf are reserved by bpf-mlir", obj.Name())
		return
	}
	a.globals = append(a.globals, g)
	a.globalByObj[obj] = g
}

// checkGlobalNames checks that global names do not collide with maps and programs (bpf-mlir's schema — the same ELF symbols). Call it after collectPrograms.
func (a *analyzer) checkGlobalNames() {
	taken := map[string]string{}
	for _, m := range a.maps {
		taken[m.Symbol] = "map"
	}
	for _, p := range a.programs {
		taken[p.Symbol] = "program"
	}
	for _, g := range a.globals {
		if what, ok := taken[g.Symbol]; ok {
			a.report(Rejected, GB009MapDeclShape, g.obj.Pos(), nil, "global %s has the same name as a %s (both are ELF symbols)", g.Symbol, what)
		}
	}
}

// globalCall lowers `G.Value()` / `G.Load()` / `G.Add(d)`. withValue is true for an expression (Value / Load) and false for a statement (Add). handled is false if the receiver is not a global.
func (l *lowerer) globalCall(call *ast.CallExpr, withValue bool) (value, bool, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return value{}, false, false
	}
	recv, ok := sel.X.(*ast.Ident)
	if !ok {
		return value{}, false, false
	}
	v, _ := l.a.info.Uses[recv].(*types.Var)
	g := l.a.globalByObj[v]
	if g == nil {
		return value{}, false, false
	}
	defer l.at(call.Pos())()
	t := vtypeOf(g.Int)
	switch sel.Sel.Name {
	case "Value", "Load":
		if !withValue {
			l.fail(Rejected, GB001UnsupportedConstruct, call.Pos(), "%s.%s() reads the global — use its value (the statement does nothing)", g.Symbol, sel.Sel.Name)
			return value{}, false, true
		}
		r := l.val()
		l.emit("%s = ebpf.global.load @%s : %s", r, g.Symbol, t.mlir())
		return value{r, t}, true, true
	case "Add":
		if withValue {
			l.fail(Rejected, GB001UnsupportedConstruct, call.Pos(), "%s.Add has no result", g.Symbol)
			return value{}, false, true
		}
		d, ok := l.expr(call.Args[0], &t)
		if !ok {
			return value{}, false, true
		}
		l.emit("ebpf.global.atomic_add @%s, %s : %s", g.Symbol, d.name, t.mlir())
		return value{}, true, true
	}
	return value{}, false, false // methods not in the table go to checkEBPFSide (GB003 / GB002)
}

// checkGlobalVarUse checks that a global variable is used only as a method receiver (as with map variables — it stops assignment, address-of and copies).
func (a *analyzer) checkGlobalVarUse(owner string, id *ast.Ident, g *GlobalVar, stack []ast.Node) {
	if sel, ok := parent(stack, 1).(*ast.SelectorExpr); ok && sel.X == ast.Expr(id) {
		return
	}
	a.report(Rejected, GB009MapDeclShape, id.Pos(), []string{owner}, "global variable %s may only be used as the receiver of its methods (no reassignment, address or copy)", g.Symbol)
}

// schemaGlobal is one entry of the schema's core.globals.
type schemaGlobal struct {
	Name    string     `json:"name"`
	Section string     `json:"section"`
	Type    *schemaInt `json:"type"`
	Note    string     `json:"note"`
}

func schemaGlobals(gs []*GlobalVar) []schemaGlobal {
	var out []schemaGlobal
	for _, g := range gs {
		kind := map[string]string{"rodata": "Config", "bss": "Global"}[g.Section]
		out = append(out, schemaGlobal{Name: g.Symbol, Section: g.Section, Type: schemaIntOf(g.Int), Note: fmt.Sprintf("Go var %s (bpf.%s)", g.Symbol, kind)})
	}
	return out
}
