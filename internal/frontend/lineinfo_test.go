package frontend

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A Go line longer than 1023 columns — auto gives GB022 (Go position), -line-info=off accepts. The long-line source is built inside the test (if gofmt
// reformatted testdata and split the long line, the test would become vacuous).
func TestLongLineLocRange(t *testing.T) {
	dir, err := os.MkdirTemp("testdata", "tmp_loc_long_line_")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	src := "package main\n\nimport \"github.com/yuskesh/go-bpf-mlir/bpf\"\n\nvar C = bpf.Array[uint32, uint64]{MaxEntries: 1}\n\n" +
		"func add1(v uint64) uint64 {\n\treturn v + 1\n}\n\n" +
		"func P(ctx *bpf.XDPContext) bpf.XDPAction {\n\tx := uint64(1)\n\tC.Update(0, x /* " + strings.Repeat("x", 1100) + " */ + add1(x))\n\treturn bpf.XDPPass\n}\n\nfunc main() {}\n"
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	auto, err := Analyze(dir)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range auto.Diagnostics {
		if d.Code == GB022LocRange && d.Verdict == Rejected && posString(d.Pos) == "main.go:13:1125" && strings.Contains(d.Msg, "shorten the line, or generate with `go tool gobpf -line-info=off`") {
			found = true
		}
	}
	if !found || auto.OK() || auto.MLIR != nil {
		for _, d := range auto.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("auto: want GB022 at main.go:13:1125 and no output")
	}
	off, err := AnalyzeWith(dir, Options{LineInfo: "off"})
	if err != nil {
		t.Fatal(err)
	}
	if !off.OK() || off.MLIR == nil {
		for _, d := range off.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("with -line-info=off a line beyond 1023 columns must be accepted")
	}
}
