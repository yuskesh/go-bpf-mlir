package frontend

import (
	"go/types"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// gobpf's exported functions and methods that take a program function value (argument `fn any` — APIs taking one per stage use names starting with fn, such as `fnIn any`) match
// the frontend's programValueTakers (the table of APIs allowed to take program function values). A type check closes the gap of a forgotten entry
// (adding a new exported API without registering it in the table, as once happened with AttachTCX).
func TestProgramValueTakersMatchGobpfAPI(t *testing.T) {
	pkgs, err := packages.Load(&packages.Config{Mode: packages.NeedName | packages.NeedTypes, Dir: repoRoot(t)}, gobpfPkg)
	if err != nil || len(pkgs) != 1 || len(pkgs[0].Errors) > 0 {
		t.Fatalf("load %s: %v %v", gobpfPkg, err, pkgs)
	}
	takesFn := func(sig *types.Signature) bool {
		for i := 0; i < sig.Params().Len(); i++ {
			p := sig.Params().At(i)
			if strings.HasPrefix(p.Name(), "fn") && types.Identical(p.Type(), types.Universe.Lookup("any").Type()) {
				return true
			}
		}
		return false
	}
	var api []string
	scope := pkgs[0].Types.Scope()
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		if fn, ok := obj.(*types.Func); ok && takesFn(fn.Type().(*types.Signature)) {
			api = append(api, gobpfPkg+"."+name)
		}
		if tn, ok := obj.(*types.TypeName); ok {
			if named, ok := tn.Type().(*types.Named); ok {
				for i := 0; i < named.NumMethods(); i++ {
					m := named.Method(i)
					if m.Exported() && takesFn(m.Type().(*types.Signature)) {
						api = append(api, gobpfPkg+"."+name+"."+m.Name())
					}
				}
			}
		}
	}
	var table []string
	for k := range programValueTakers {
		table = append(table, k)
	}
	sort.Strings(api)
	sort.Strings(table)
	t.Logf("gobpf API taking fn any: %v", api)
	if len(api) == 0 || len(api) != len(table) {
		t.Fatalf("gobpf's API taking a program function %v differs from programValueTakers %v", api, table)
	}
	for i := range api {
		if api[i] != table[i] {
			t.Fatalf("gobpf's API taking a program function %v differs from programValueTakers %v", api, table)
		}
	}
}
