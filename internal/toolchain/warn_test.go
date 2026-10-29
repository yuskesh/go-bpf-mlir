package toolchain

import (
	"strings"
	"testing"
)

// Reading ebpf-compile's stderr with rc 0. The input is the stderr of the pinned ebpf-compile on two bpf-mlir test inputs
// (one warning with a note, two warnings at the same loc each with its own note).

const nonrootIndexWarningSample = `loc("idx_const.mlir":19:11): warning: the index of ebpf.ref.index can be a constant on one path and a non-constant value on another — loaders without CAP_PERFMON were observed to reject this pointer arithmetic on some kernels; keep the default out of the index (put the ref.index inside the present region) or make the default non-constant
loc("idx_const.mlir":12:10): note: the constant index comes from here
loc("g_mdim.mlir":49:11): warning: the index of ebpf.ref.index can be a constant on one path and a non-constant value on another — loaders without CAP_PERFMON were observed to reject this pointer arithmetic on some kernels; keep the default out of the index (put the ref.index inside the present region) or make the default non-constant
loc("g_mdim.mlir":33:10): note: the constant index comes from here
loc("g_mdim.mlir":49:11): warning: the index of ebpf.ref.index can be a constant on one path and a non-constant value on another — loaders without CAP_PERFMON were observed to reject this pointer arithmetic on some kernels; keep the default out of the index (put the ref.index inside the present region) or make the default non-constant
loc("g_mdim.mlir":11:10): note: the constant index comes from here
`

func TestCompileWarningsNonrootIndex(t *testing.T) {
	ws, err := CompileWarnings(nonrootIndexWarningSample)
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 3 {
		t.Fatalf("want 3 warnings, got %d: %+v", len(ws), ws)
	}
	w := ws[0]
	if w.File != "idx_const.mlir" || w.Line != 19 || w.Col != 11 || !strings.HasPrefix(w.Msg, "the index of ebpf.ref.index") || len(w.Notes) != 1 || w.Notes[0].Line != 12 || w.Notes[0].Col != 10 || w.Notes[0].Msg != "the constant index comes from here" {
		t.Fatalf("first warning: %+v", w)
	}
	if ws[1].Notes[0].Line != 33 || ws[2].Notes[0].Line != 11 {
		t.Fatalf("each warning keeps its own note: %+v", ws)
	}
	if ws, err := CompileWarnings(""); err != nil || len(ws) != 0 {
		t.Fatalf("empty stderr: %v %v", ws, err)
	}
}

// A line that is not a warning / note (error: included) and a note before any warning are errors naming the original line and saying "update gobpf's reading".
func TestCompileWarningsRefuseUnknownLines(t *testing.T) {
	for _, bad := range []string{
		`loc("main.go":3:4): error: something failed`,
		`loc("main.go":3:4): note: a note without a warning`,
		`ebpf-compile: some new diagnostic`,
		`loc("main.go":3:4): remark: a new kind`,
	} {
		_, err := CompileWarnings(nonrootIndexWarningSample + bad + "\n")
		if bad == `loc("main.go":3:4): note: a note without a warning` {
			_, err = CompileWarnings(bad + "\n")
		}
		if err == nil || !strings.Contains(err.Error(), "update gobpf's reading of it") || !strings.Contains(err.Error(), bad) {
			t.Fatalf("%q: want the refusal naming the line, got %v", bad, err)
		}
	}
}

// The rewrite on failure (RewriteLocs) does not turn a warning into an error — the line kind stays in the text after the rewrite to Go positions.
func TestRewriteLocsKeepsWarning(t *testing.T) {
	got := RewriteLocs(`loc("idxdef.go":28:3): warning: the index of ebpf.ref.index …
loc("idxdef.go":22:7): note: the constant index comes from here
loc("idxdef.go":30:1): error: a real error`, "internal/difftest/idxdef")
	for _, want := range []string{
		"internal/difftest/idxdef/idxdef.go:28:3: ebpf-compile: warning: the index",
		"internal/difftest/idxdef/idxdef.go:22:7: ebpf-compile: note: the constant index",
		"internal/difftest/idxdef/idxdef.go:30:1: ebpf-compile: error: a real error",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("RewriteLocs lost %q:\n%s", want, got)
		}
	}
	if strings.Count(got, "error:") != 1 {
		t.Fatalf("RewriteLocs turned a warning into an error:\n%s", got)
	}
}
