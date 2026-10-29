package gobpf

import (
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/yuskesh/go-bpf-mlir/bindrt"

	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// Global variables (the same order as bpf-mlir's LoadObjectsWithRodata): CheckGlobals without touching the kernel (bpf-mlir's go/layout independently compares the ELF symbols, the BTF DATASEC and
// the generated declarations — cilium does not look at VAR types) → **a non-Optional Config that was not Set is
// a Load error** (never runs silently with 0) → set .rodata with cilium's VariableSpec.Set → load → bind the Variables.

// Global is a global variable the generated file registers (Var is a pointer to a bpf.Config / bpf.Global variable).
type Global struct {
	Symbol string
	Var    any
	Pos    string // position of the Go declaration (for error messages)
}

// gobpfGlobal is the marker method of bpf.Config / bpf.Global.
type gobpfGlobal interface {
	GobpfGlobal() (section string, t reflect.Type, optional bool)
}

// ConfigNotSetError lists the (non-Optional) Configs that were not Set before Load.
type ConfigNotSetError struct {
	Configs []Global
}

func (e *ConfigNotSetError) Error() string {
	var parts []string
	for _, g := range e.Configs {
		parts = append(parts, fmt.Sprintf("%s (%s)", g.Symbol, g.Pos))
	}
	return fmt.Sprintf("gobpf: config %s not set — call <Config>.Set(v) before gobpf.Load, or declare it bpf.Config[T]{Optional: true} to load it as 0", strings.Join(parts, ", "))
}

func current0() *Object {
	o, _ := current()
	return o
}

// globalDecls turns the generated file's global declarations into bindrt GlobalDecls (since bpf-mlir v0.15.0, the same single CheckMapDecls as the map declarations
// checks the ELF symbols, the BTF DATASEC VARs and the INT widths and signs in both directions. Up to v0.14.0 layout.CheckGlobals was called separately).
// An empty slice (not nil) declares "no globals" — a global in the ELF with no declaration is a mismatch.
func globalDecls(o *Object) ([]bindrt.GlobalDecl, error) {
	gs := make([]bindrt.GlobalDecl, 0, len(o.Globals))
	for _, g := range o.Globals {
		m, ok := g.Var.(gobpfGlobal)
		if !ok {
			return nil, fmt.Errorf("gobpf: global %s: %T is not a bpf.Config / bpf.Global declaration (%s)", g.Symbol, g.Var, regenerateHint)
		}
		sec, t, _ := m.GobpfGlobal()
		sp, ok := intSpelling[t.Kind()]
		if !ok {
			return nil, fmt.Errorf("gobpf: global %s: %s is not a fixed-width integer (%s)", g.Symbol, t, regenerateHint)
		}
		gs = append(gs, bindrt.GlobalDecl{Name: g.Symbol, Section: sec, Type: sp})
	}
	return gs, nil
}

// configsSet names the non-Optional Configs that were not Set (without touching the kernel — Load calls it before the caps probe, LoadUnchecked before load).
func configsSet(o *Object) error {
	var missing []Global
	for _, g := range o.Globals {
		m, ok := g.Var.(gobpfGlobal)
		if !ok {
			continue
		}
		sec, _, optional := m.GobpfGlobal()
		if sec != "rodata" || optional {
			continue
		}
		if _, set := binding.Pending(g.Var); !set {
			missing = append(missing, g)
		}
	}
	if len(missing) > 0 {
		return &ConfigNotSetError{Configs: missing}
	}
	return nil
}

// setRodata writes the values of Set Configs into .rodata (an Optional Config that was not Set keeps the ELF's 0).
func setRodata(o *Object, spec *ebpf.CollectionSpec) error {
	if o == nil {
		return nil
	}
	if err := configsSet(o); err != nil {
		return err
	}
	for _, g := range o.Globals {
		v, set := binding.Pending(g.Var)
		if !set {
			continue
		}
		vs, ok := spec.Variables[g.Symbol]
		if !ok {
			return fmt.Errorf("gobpf: config %s (%s): the embedded ELF has no variable %q (%s)", g.Symbol, g.Pos, g.Symbol, regenerateHint)
		}
		if err := vs.Set(v); err != nil {
			return fmt.Errorf("gobpf: setting config %s (%s): %w", g.Symbol, g.Pos, err)
		}
	}
	return nil
}

// bindGlobals binds the loaded Variables to the global variables.
func bindGlobals(o *Object, coll *ebpf.Collection) error {
	for _, g := range o.Globals {
		v, ok := coll.Variables[g.Symbol]
		if !ok {
			return fmt.Errorf("gobpf: the loaded collection has no variable %q (%s)", g.Symbol, regenerateHint)
		}
		if err := binding.BindGlobal(g.Var, v); err != nil {
			return err
		}
	}
	return nil
}

// onlyGlobalProblems reports whether err is a *MapDeclError with only global mismatches (bindrt kinds "global" / "global_missing_in_elf" / "global_undeclared").
func onlyGlobalProblems(err error) bool {
	var me *MapDeclError
	if !errors.As(err, &me) || len(me.Problems) == 0 {
		return false
	}
	for _, pr := range me.Problems {
		if !strings.HasPrefix(pr.Field, "global") {
			return false
		}
	}
	return true
}
