package toolchain

import (
	"testing"
)

// The ebpf-compile version check.

// The control for the rewrite — loc-less lines, loc(unknown), a loc with an absolute path and note continuations stay unchanged.
func TestRewriteLocsLeavesOtherLines(t *testing.T) {
	in := "loc(\"main.go\":3:4): error: boom\n" +
		"error: ebpf-compile itself failed\n" +
		"loc(unknown): error: no position\n" +
		"loc(\"/abs/gobpf.mlir\":9:1): error: absolute\n" +
		"  %0 = \"ebpf.call\"(%arg0) : (i32) -> i32\n"
	want := "pkg/main.go:3:4: ebpf-compile: error: boom\n" +
		"error: ebpf-compile itself failed\n" +
		"loc(unknown): error: no position\n" +
		"loc(\"/abs/gobpf.mlir\":9:1): error: absolute\n" +
		"  %0 = \"ebpf.call\"(%arg0) : (i32) -> i32\n"
	if got := RewriteLocs(in, "pkg"); got != want {
		t.Fatalf("got:\n%s\nwant:\n%s", got, want)
	}
}
