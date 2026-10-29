package gobpf

import (
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/livecaps"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// Tests of the checked load. The oracle is LoadObjects in bpf-mlir v0.2.0's examples/go/xdp-counter/objects_gen.go and precheck_test.go.
// The embedded object is the generated files of examples/xdpcount (gobpf.bpf.o and the schema hash in gobpf_gen.go).

func repoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), ".."))
}

var testCounts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func testProgram(ctx *bpf.XDPContext) bpf.XDPAction { return bpf.XDPPass }

func exampleObject(t *testing.T) Object {
	t.Helper()
	dir := filepath.Join(repoRoot(), "examples", "xdpcount")
	elf, err := os.ReadFile(filepath.Join(dir, "gobpf.bpf.o"))
	if err != nil {
		t.Fatal(err)
	}
	gen, err := os.ReadFile(filepath.Join(dir, "gobpf_gen.go"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`SchemaSHA256: "([0-9a-f]{64})"`).FindSubmatch(gen)
	if m == nil {
		t.Fatal("no SchemaSHA256 in gobpf_gen.go")
	}
	return Object{
		ELF: elf, SchemaSHA256: string(m[1]),
		Maps:     []Map{{Symbol: "Counts", Var: &testCounts}},
		Programs: []Program{{Symbol: "CountPackets", Kind: "xdp", Func: testProgram}},
	}
}

// reset restores the registration and load state for each test (only tests inside the package touch it).
func reset(t *testing.T) {
	t.Helper()
	mu.Lock()
	if loadedObjs != nil {
		loadedObjs.coll.Close()
	}
	registered, loadedObjs = nil, nil
	mu.Unlock()
	binding.ResetForTest()
}

// --- fake caps (the same shape as probeErrCaps in precheck_test.go) ---

type fakeCaps struct {
	progType func() (bool, error)
	helper   func() (bool, error)
}

func (c fakeCaps) HasProgType(string, int64) (bool, error) {
	if c.progType != nil {
		return c.progType()
	}
	return true, nil
}
func (c fakeCaps) HasHelper(string, int64, string, int64) (bool, error) {
	if c.helper != nil {
		return c.helper()
	}
	return true, nil
}
func (fakeCaps) HasMapType(string, int64) (bool, error)                         { return true, nil }
func (fakeCaps) HasBTFFeature(string) (bool, error)                             { return true, nil }
func (fakeCaps) HasArgTagSemantics(string, int64, string, string) (bool, error) { return true, nil }
func (fakeCaps) AllowsMapField(string, int64, string) (bool, error)             { return true, nil }
func (fakeCaps) CheckFunc(string) ([]string, error)                             { return nil, nil }

var (
	probeErr = fakeCaps{progType: func() (bool, error) {
		return false, fmt.Errorf("detect support for XDP: %w", &ebpf.VerifierError{Cause: syscall.EPERM})
	}}
	blocking     = fakeCaps{progType: func() (bool, error) { return false, nil }}
	helperUnkown = fakeCaps{helper: func() (bool, error) { return false, fmt.Errorf("probe: %w", requirements.ErrUnknown) }}
)

func assertNotLoaded(t *testing.T) {
	t.Helper()
	mu.Lock()
	l := loadedObjs
	mu.Unlock()
	if l != nil {
		t.Fatal("a kernel object was loaded although the precheck stopped")
	}
	if _, err := testCounts.Get(0); err == nil || !strings.Contains(err.Error(), "not loaded yet") {
		t.Fatalf("the map variable must stay unloaded, Get: %v", err)
	}
}

// Without an embedded object, a named error.
func TestLoadWithoutObject(t *testing.T) {
	reset(t)
	if _, _, err := Load(blocking); !errors.Is(err, ErrNoObject) {
		t.Fatalf("want ErrNoObject, got %v", err)
	}
	if _, err := LoadUnchecked(nil); !errors.Is(err, ErrNoObject) {
		t.Fatalf("want ErrNoObject, got %v", err)
	}
}

// nil caps never skip the check; they give a *PrecheckError (objects_gen.go: CheckTarget's "no capabilities given" wrapped in a PrecheckError).
func TestLoadNilCaps(t *testing.T) {
	reset(t)
	Register(exampleObject(t))
	_, _, err := Load(nil)
	var pe *PrecheckError
	if !errors.As(err, &pe) || !strings.Contains(pe.Err.Error(), "no capabilities given (the check is not skipped)") {
		t.Fatalf("want *PrecheckError(no capabilities given), got %T %v", err, err)
	}
	if _, err := CheckTarget(nil); err == nil || !strings.Contains(err.Error(), "no capabilities given") {
		t.Fatalf("CheckTarget(nil) must fail: %v", err)
	}
	assertNotLoaded(t)
}

// A probe error is a *PrecheckError whose cause (EPERM wrapped in a VerifierError) is reachable with Unwrap. It can be told apart before VerifierError.
func TestLoadProbeError(t *testing.T) {
	reset(t)
	Register(exampleObject(t))
	_, _, err := Load(probeErr)
	var pe *PrecheckError
	if !errors.As(err, &pe) {
		t.Fatalf("want *PrecheckError, got %T %v", err, err)
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) || !errors.Is(err, syscall.EPERM) {
		t.Fatalf("the cause must be reachable with Unwrap: %v", err)
	}
	if !strings.Contains(err.Error(), "before loading the embedded program") { // bindrt's messages are in English since bpf-mlir go/v1.19.0

		t.Fatalf("the message must say the program was not loaded: %v", err)
	}
	assertNotLoaded(t)
}

// A BlocksLoad Unmet is a *TargetError and creates no kernel object.
func TestLoadBlockingUnmet(t *testing.T) {
	reset(t)
	Register(exampleObject(t))
	_, _, err := Load(blocking)
	var te *TargetError
	if !errors.As(err, &te) || len(te.Unmet) == 0 || te.Unmet[0].Kind != "program_type" {
		t.Fatalf("want *TargetError(program_type), got %T %v", err, err)
	}
	if !strings.Contains(err.Error(), "does not satisfy this object's requirements (not loaded)") {
		t.Fatalf("message: %v", err)
	}
	assertNotLoaded(t)
}

// A non-blocking Unknown (helper_unknown) passes the precheck and reaches the load stage. As root it loads and returns the Unknown.
// Without root the kernel refuses (the error is neither a TargetError nor a PrecheckError — an error of the load stage).
func TestLoadNonBlockingUnknownProceeds(t *testing.T) {
	reset(t)
	Register(exampleObject(t))
	objs, rest, err := Load(helperUnkown)
	var te *TargetError
	var pe *PrecheckError
	if errors.As(err, &te) || errors.As(err, &pe) {
		t.Fatalf("a non-blocking Unknown must not stop the precheck: %v", err)
	}
	if os.Geteuid() != 0 {
		if err == nil {
			objs.Close()
			t.Fatal("expected the kernel to refuse a non-root load")
		}
		t.Logf("non-root: the load stage was reached and refused by the kernel: %v", err)
		return
	}
	if err != nil {
		t.Fatalf("root load: %v", err)
	}
	defer objs.Close()
	if len(rest) == 0 || rest[0].Kind != "helper_unknown" {
		t.Fatalf("the non-blocking Unknown must be returned, got %v", rest)
	}
}

// The only load without the check is named LoadUnchecked (the same rule as bpf-mlir's bindgen — checked statically).
func TestOnlyUncheckedSkipsTheCheck(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filepath.Join(repoRoot(), "gobpf", "gobpf.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var loaders []string
	for _, d := range f.Decls {
		if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && ast.IsExported(fd.Name.Name) && strings.HasPrefix(fd.Name.Name, "Load") {
			loaders = append(loaders, fd.Name.Name)
		}
	}
	sort.Strings(loaders)
	if strings.Join(loaders, ",") != "Load,LoadCollectionSpec,LoadUnchecked" {
		t.Fatalf("exported loaders changed: %v (the unchecked path must be named Unchecked; LoadCollectionSpec is the documented low-level path)", loaders)
	}
}

// Get before Load is a named error (no root needed).
func TestGetBeforeLoad(t *testing.T) {
	reset(t)
	Register(exampleObject(t))
	_, err := testCounts.Get(0)
	if err == nil || !strings.Contains(err.Error(), "Array.Get: map Counts is not loaded yet (call gobpf.Load first)") {
		t.Fatalf("Get before Load: %v", err)
	}
	var unregistered bpf.Array[uint32, uint64]
	if _, err := unregistered.Get(0); err == nil || !strings.Contains(err.Error(), "not in the generated binding") {
		t.Fatalf("Get on an unregistered variable: %v", err)
	}
}

// (root) Get after an actual load, Load twice, and Get after Close.
func TestMapHandleLifecycleRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root (run: go test -exec sudo ./gobpf) — the root run is a separate step")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	reset(t)
	Register(exampleObject(t))
	objs, rest, err := Load(livecaps.New())
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	for _, u := range rest {
		t.Logf("undetermined: %s", u.String())
	}
	if v, err := testCounts.Get(0); err != nil || v != 0 {
		t.Fatalf("Get after Load: %v %v", v, err)
	}
	if _, _, err := Load(livecaps.New()); !errors.Is(err, ErrAlreadyLoaded) {
		t.Fatalf("second Load: want ErrAlreadyLoaded, got %v", err)
	}
	if _, err := LoadUnchecked(nil); !errors.Is(err, ErrAlreadyLoaded) {
		t.Fatalf("LoadUnchecked while loaded: want ErrAlreadyLoaded, got %v", err)
	}
	if _, err := objs.Program(testProgram); err != nil {
		t.Fatalf("Program: %v", err)
	}
	objs.Close()
	if _, err := testCounts.Get(0); err == nil || !strings.Contains(err.Error(), "Array.Get: map Counts is closed (Objects.Close was called)") {
		t.Fatalf("Get after Close: %v", err)
	}
	if _, err := objs.Program(testProgram); err == nil {
		t.Fatal("Program after Close must fail")
	}
	// After Close it can load again.
	objs2, _, err := Load(livecaps.New())
	if err != nil {
		t.Fatalf("Load after Close: %v", err)
	}
	objs2.Close()
}
