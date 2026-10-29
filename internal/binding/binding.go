// Package binding is the registry that binds the map variables a user declares (bpf.Array and the like) to the loaded kernel maps.
//
// Both bpf (the declaration types) and gobpf (the runtime) use it, and users cannot see it (internal).
// It is keyed by variable address — user variables are package-level and never move (the frontend refuses taking their address and reassigning them).
package binding

import (
	"fmt"
	"sync"

	"github.com/cilium/ebpf"
)

type state int

const (
	declared state = iota // registered by the generated file (before load)
	loaded                // after gobpf.Load
	closed                // after Objects.Close
)

type entry struct {
	symbol string
	st     state
	m      *ebpf.Map
	inner  *ebpf.MapSpec // the inner template of a map-in-map (cilium's spec InnerMap)
}

// BindInner binds the inner template spec of a map-in-map outer map (after Bind — NewInner creates maps in the template's shape).
func BindInner(key any, spec *ebpf.MapSpec) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := entries[key]; ok {
		e.inner = spec
	}
}

// InnerSpec returns the inner template spec of an outer map (nil if none).
func InnerSpec(key any) *ebpf.MapSpec {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := entries[key]; ok && e.st == loaded {
		return e.inner
	}
	return nil
}

var (
	mu      sync.Mutex
	entries = map[any]*entry{}
)

// Declare is called from the generated file's init: key is a pointer to the user's variable, symbol is the schema map name.
func Declare(key any, symbol string) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := entries[key]; ok {
		panic(fmt.Sprintf("gobpf: map variable %s is declared twice (as %s)", symbol, e.symbol))
	}
	entries[key] = &entry{symbol: symbol}
}

// Symbol returns the registered name ("" if not registered).
func Symbol(key any) string {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := entries[key]; ok {
		return e.symbol
	}
	return ""
}

// Bind binds a loaded map.
func Bind(key any, m *ebpf.Map) error {
	mu.Lock()
	defer mu.Unlock()
	e, ok := entries[key]
	if !ok {
		return fmt.Errorf("gobpf: internal error: binding an undeclared map variable")
	}
	e.m, e.st = m, loaded
	return nil
}

// Unbind moves to the after-Close state (the caller closes the map).
func Unbind(key any) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := entries[key]; ok {
		e.m, e.st = nil, closed
	}
}

// Map returns the loaded map. Before load, after Close and when not registered, it returns a distinct named error.
func Map(key any, method string) (*ebpf.Map, error) {
	mu.Lock()
	defer mu.Unlock()
	e, ok := entries[key]
	if !ok {
		return nil, fmt.Errorf("%s: this map variable is not in the generated binding (run go generate — the variable must be a package-level map declaration)", method)
	}
	switch e.st {
	case declared:
		return nil, fmt.Errorf("%s: map %s is not loaded yet (call gobpf.Load first)", method, e.symbol)
	case closed:
		return nil, fmt.Errorf("%s: map %s is closed (Objects.Close was called)", method, e.symbol)
	}
	return e.m, nil
}

// ResetForTest empties the registry (only tests inside the gobpf package use it).
func ResetForTest() {
	mu.Lock()
	defer mu.Unlock()
	entries = map[any]*entry{}
	globals = map[any]*globalEntry{}
}

// ResetPendingForTest forgets every pre-Load Set of globals (tests only — to see an Optional Config's default 0 many times in one process).
func ResetPendingForTest() {
	mu.Lock()
	defer mu.Unlock()
	for _, e := range globals {
		e.pending, e.set = nil, false
	}
}

// --- global variables (bpf.Config in .rodata, bpf.Global in .bss) ---

type globalEntry struct {
	symbol  string
	st      state
	v       *ebpf.Variable
	pending any  // the value Set before Load (.rodata)
	set     bool // pending is present
}

var globals = map[any]*globalEntry{}

// DeclareGlobal is called from the generated file's init: key is a pointer to the user's variable, symbol is the schema global name.
func DeclareGlobal(key any, symbol string) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := globals[key]; ok {
		panic(fmt.Sprintf("gobpf: global variable %s is declared twice (as %s)", symbol, e.symbol))
	}
	globals[key] = &globalEntry{symbol: symbol}
}

// SetPending remembers a .rodata value before Load. After load it is an error (the kernel freezes .rodata).
func SetPending(key any, method string, v any) error {
	mu.Lock()
	defer mu.Unlock()
	e, ok := globals[key]
	if !ok {
		return fmt.Errorf("%s: this variable is not in the generated binding (run go generate — the variable must be a package-level bpf.Config declaration)", method)
	}
	if e.st == loaded {
		return fmt.Errorf("%s: config %s is frozen after gobpf.Load (the kernel freezes .rodata) — set it before Load", method, e.symbol)
	}
	e.pending, e.set = v, true
	return nil
}

// Pending returns the value Set before Load (ok = false if none).
func Pending(key any) (any, bool) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := globals[key]; ok && e.set {
		return e.pending, true
	}
	return nil, false
}

// BindGlobal binds a loaded global variable.
func BindGlobal(key any, v *ebpf.Variable) error {
	mu.Lock()
	defer mu.Unlock()
	e, ok := globals[key]
	if !ok {
		return fmt.Errorf("gobpf: internal error: binding an undeclared global variable")
	}
	e.v, e.st = v, loaded
	return nil
}

// UnbindGlobal moves to the after-Close state.
func UnbindGlobal(key any) {
	mu.Lock()
	defer mu.Unlock()
	if e, ok := globals[key]; ok {
		e.v, e.st = nil, closed
	}
}

// Variable returns the loaded global variable. Before load, after Close and when not registered, it returns a named error.
func Variable(key any, method string) (*ebpf.Variable, error) {
	mu.Lock()
	defer mu.Unlock()
	e, ok := globals[key]
	if !ok {
		return nil, fmt.Errorf("%s: this variable is not in the generated binding (run go generate — the variable must be a package-level bpf.Config / bpf.Global declaration)", method)
	}
	switch e.st {
	case declared:
		return nil, fmt.Errorf("%s: global %s is not loaded yet (call gobpf.Load first)", method, e.symbol)
	case closed:
		return nil, fmt.Errorf("%s: global %s is closed (Objects.Close was called)", method, e.symbol)
	}
	return e.v, nil
}
