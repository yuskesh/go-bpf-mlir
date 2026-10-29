package frontend

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Rules R1 / R2 for call paths inside loops (callloop.go).

// The check-off switches are for tests only — no non-test source in the package assigns checkLoopCallPaths / checkRingbufFit
// (the production build always checks).
func TestLoopCallCheckSwitchTestOnly(t *testing.T) {
	if !checkLoopCallPaths || !checkRingbufFit || !checkWinArgs {
		t.Fatal("checkLoopCallPaths, checkRingbufFit and checkWinArgs must be true by default")
	}
	fset := token.NewFileSet()
	files, _ := filepath.Glob("*.go")
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		n++
		ast.Inspect(af, func(m ast.Node) bool {
			if as, ok := m.(*ast.AssignStmt); ok {
				for _, lhs := range as.Lhs {
					if id, ok := lhs.(*ast.Ident); ok && (id.Name == "checkLoopCallPaths" || id.Name == "checkRingbufFit" || id.Name == "checkWinArgs") {
						t.Errorf("%s: %s is assigned outside the tests", fset.Position(id.Pos()), id.Name)
					}
				}
			}
			return true
		})
	}
	if n < 10 {
		t.Fatalf("parsed only %d non-test files — the scan did not see the package", n)
	}
}

// Precondition: the call graph is a DAG — GB010 stops recursion (callloop.go's summary does not handle recursion).
func TestLoopCallDAGPrecondition(t *testing.T) {
	for _, dir := range []string{"recursion_direct", "recursion_mutual"} {
		res, err := analyzeCached(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, d := range res.Diagnostics {
			found = found || (d.Code == GB010Recursion && d.Verdict == Rejected)
		}
		if !found || res.OK() {
			t.Fatalf("%s: recursion must be rejected with GB010 (the loop call path summary assumes a DAG)", dir)
		}
	}
}

// The (U) estimate counts a call as one op — however large the callee, the loop does not stop on the estimate (the Helper64 shape).
func TestLoopCallUnrollEstimateCountsCallOnce(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "cl_big_body_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("a 64-count loop calling a large subprogram must pass the unroll estimate")
	}
	if !strings.Contains(string(res.MLIR), "ebpf.loop 64 unroll") || !strings.Contains(string(res.MLIR), "ebpf.call @mix") {
		t.Fatal("expected ebpf.loop 64 unroll with ebpf.call @mix in the generated .mlir")
	}
}
