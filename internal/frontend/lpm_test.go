package frontend

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuskesh/go-bpf-mlir/bpf"
)

// Lowering of lpm_trie.

// TestLoweringPanicIsInternalError: a panic during lowering does not crash the process and becomes GB015 at the function's position.
func TestLoweringPanicIsInternalError(t *testing.T) {
	lowerPanicHook = func(name string) {
		if name == "P" {
			panic("injected")
		}
	}
	defer func() { lowerPanicHook = nil }()
	res, err := Analyze(filepath.Join("testdata", "lpm_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if res.OK() || res.MLIR != nil {
		t.Fatal("a panicking lowering must block the output")
	}
	for _, d := range res.Diagnostics {
		if d.Code == GB015InternalEmitter && d.Verdict == Unknown && strings.Contains(d.String(), "main.go:9:6") && strings.Contains(d.Msg, "panicked while lowering P: injected") {
			return
		}
	}
	t.Fatalf("want GB015 at main.go:9:6, got %v", res.Diagnostics)
}

// The LPMTrie4 flags that gobpf's Load passes for the map declaration (bpf's GobpfMapFlags) equal the flags the frontend writes to the schema and ELF
// (bpf-mlir stops before load if the declared flags differ from the ELF; this catches a mismatch between the two places before generate).
func TestLPMFlagsMatchRuntime(t *testing.T) {
	if got := (&bpf.LPMTrie4[uint32]{}).GobpfMapFlags(); got != lpmNoPrealloc {
		t.Fatalf("bpf.LPMTrie4.GobpfMapFlags() = %d, the frontend emits flags %d", got, lpmNoPrealloc)
	}
}
