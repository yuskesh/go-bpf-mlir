package uprobeabi

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// The production build (no tag) has no entry to the file offset mutation — builds greetwatch (the uprobe example) without the tag and
// with gobpf_uprobe_mutant, and checks that the env name selecting the mutation is absent from the untagged binary and present in the tagged one (the control).
func TestNoMutantInProductBuild(t *testing.T) {
	if mutantBuild {
		t.Skip("this test binary is the gobpf_uprobe_mutant build (the check is for the product build)")
	}
	if testing.Short() {
		t.Skip("builds examples/greetwatch twice")
	}
	goBin := filepath.Join(runtime.GOROOT(), "bin", "go")
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	marker := []byte("GOBPF_UPROBE_" + "MUTANT") // do not put the same string as one literal into this test binary itself
	for _, c := range []struct {
		tags string
		want bool
	}{{"", false}, {"gobpf_uprobe_mutant", true}} {
		out := filepath.Join(dir, "greetwatch-"+c.tags)
		args := []string{"build", "-o", out}
		if c.tags != "" {
			args = append(args, "-tags", c.tags)
		}
		cmd := exec.Command(goBin, append(args, "./examples/greetwatch")...)
		cmd.Dir = root
		if b, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go %v: %v\n%s", args, err, b)
		}
		bin, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		if got := bytes.Contains(bin, marker); got != c.want {
			t.Errorf("tags %q: the binary contains the mutant entry %q = %v, want %v", c.tags, marker, got, c.want)
		}
		t.Logf("tags %q: mutant entry in the binary = %v (%d bytes)", c.tags, bytes.Contains(bin, marker), len(bin))
	}
}
