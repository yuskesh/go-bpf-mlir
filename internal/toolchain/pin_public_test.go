package toolchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeCompiler writes an ebpf-compile stand-in that only answers --version with the given bpf-mlir line.
func fakeCompiler(t *testing.T, line string) string {
	p := filepath.Join(t.TempDir(), "ebpf-compile")
	script := "#!/bin/sh\nif [ \"$1\" = --version ]; then printf 'LLVM (http://llvm.org/):\\n  LLVM version 23.1.1\\n" + line + "'; exit 0; fi\necho 'fake ebpf-compile must not be run to compile' >&2; exit 99\n"
	if err := os.WriteFile(p, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// The public tree accepts the ebpf-compile of the bpf-mlir v1.20.0 source release, with the module version standing for the copied packages.
func TestPublicPinAccepts(t *testing.T) {
	v, err := Check(fakeCompiler(t, "bpf-mlir "+PinnedCompilerVersion+" (commit "+PinnedCompilerCommit+")\\n"), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if v.Describe != PinnedCompilerVersion || v.Commit != PinnedCompilerCommit || v.Module != PinnedModuleVersion || v.Submodule != "" {
		t.Fatalf("unexpected %+v", v)
	}
}

// The public tree refuses other compilers with a named error: the development pin, -dirty, unknown and no version line.
func TestPublicPinRejects(t *testing.T) {
	const devCommit = "ab0db4b40c0544cf83f551f8998af51f4dde26aa"
	cases := map[string]struct{ line, want string }{
		"dev_commit": {"bpf-mlir go/v1.19.0-54-gab0db4b40 (commit " + devCommit + ")\\n", "but gobpf needs exactly bpf-mlir commit " + PinnedCompilerCommit},
		"dirty":      {"bpf-mlir " + PinnedCompilerVersion + "-dirty (commit " + PinnedCompilerCommit + ")\\n", "a build from modified or unidentified source"},
		"unknown":    {"bpf-mlir unknown (commit " + PinnedCompilerCommit + ")\\n", `bpf-mlir "unknown"`},
		"no_line":    {"", "has no `bpf-mlir <version> (commit <sha>)` line"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Check(fakeCompiler(t, c.line), t.TempDir())
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "source release (commit "+PinnedCompilerCommit+")") {
				t.Fatalf("want an error containing %q and the release remedy, got %v", c.want, err)
			}
		})
	}
}

// A module version other than the copied packages' stand-in stops (Verify is also reachable with an explicit version).
func TestPublicPinModule(t *testing.T) {
	line := "bpf-mlir " + PinnedCompilerVersion + " (commit " + PinnedCompilerCommit + ")\n"
	if _, err := Verify(line, "v1.19.0", ""); err == nil || !strings.Contains(err.Error(), "copied into this tree") {
		t.Fatalf("want a refusal of an explicit module version, got %v", err)
	}
}
