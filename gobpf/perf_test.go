package gobpf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/yuskesh/go-bpf-mlir/bpf"
)

// A stack trace map whose Depth exceeds the host's kernel.perf_event_max_stack stops with a named error before the map is created
// (the test cannot lower the sysctl, so it swaps the path). An unreadable sysctl does not stop; it returns a note to add to a map creation error.
func TestCheckStackDepth(t *testing.T) {
	dir := t.TempDir()
	sysctl := filepath.Join(dir, "perf_event_max_stack")
	if err := os.WriteFile(sysctl, []byte("127\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	saved := perfMaxStackPath
	defer func() { perfMaxStackPath = saved }()
	perfMaxStackPath = sysctl
	ok := &Object{Maps: []Map{{Symbol: "S", Var: &bpf.StackTrace{MaxEntries: 8, Depth: 127}, Pos: "main.go:5:5"}}}
	if note, err := checkStackDepth(ok); err != nil || !strings.Contains(note, "(127 here)") {
		t.Fatalf("Depth 127 with max 127: note %q err %v", note, err)
	}
	over := &Object{Maps: []Map{{Symbol: "S", Var: &bpf.StackTrace{MaxEntries: 8, Depth: 128}, Pos: "main.go:5:5"}}}
	if _, err := checkStackDepth(over); err == nil || !strings.Contains(err.Error(), "stack trace map S (main.go:5:5): Depth 128 exceeds kernel.perf_event_max_stack 127 on this host") {
		t.Fatalf("Depth 128 with max 127: %v", err)
	}
	perfMaxStackPath = filepath.Join(dir, "missing")
	if note, err := checkStackDepth(over); err != nil || !strings.Contains(note, "could not be read") {
		t.Fatalf("unreadable sysctl: note %q err %v", note, err)
	}
	none := &Object{Maps: []Map{{Symbol: "A", Var: &bpf.Array[uint32, uint64]{MaxEntries: 1}}}}
	if note, err := checkStackDepth(none); err != nil || note != "" {
		t.Fatalf("no stack trace map: note %q err %v", note, err)
	}
}
