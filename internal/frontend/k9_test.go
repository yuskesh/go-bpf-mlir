package frontend

import (
	"path/filepath"
	"testing"
)

// The limit itself (MaxEntries 1073741823 — 4 × N = 4294967292 ≤ U32_MAX) is accepted (only one above it, the negative case map_k9, stops — the boundary control).
// The accepted .mlir and schema pass ebpf-compile (including the K9 check).
func TestMapSizeLimitEdgeOK(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "map_k9_edge_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("MaxEntries 1073741823 must be accepted (the limit itself)")
	}
}
