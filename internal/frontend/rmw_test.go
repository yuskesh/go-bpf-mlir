package frontend

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"
)

// Shapes the non-atomic RMW rule accepts — per-CPU maps, WithLock's lock record, keys shown to differ (different constants), another map,
// a store to another field of the same record, a timer callback's own value (the program side only reads) — all generate.
func TestNonAtomicRMWAcceptedForms(t *testing.T) {
	for _, dir := range []string{"rmw_ok_percpu", "rmw_ok_withlock", "rmw_ok_other_key", "rmw_ok_other_map", "rmw_ok_other_field", "rmw_ok_callback", "keyproof_ok", "timer_guard_forms_ok", "rmwx_ok_across", "mig1_after", "mig2_after", "mig3_after", "ga_ok"} {
		res, err := Analyze(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range res.Diagnostics {
			if d.Code == GB028NonAtomicRMW || d.Code == GB021AtomicShape {
				t.Errorf("%s: %s", dir, d.String())
			}
		}
		if !res.OK() {
			for _, d := range res.Diagnostics {
				t.Log(d.String())
			}
			t.Errorf("%s must generate", dir)
		}
	}
}

// Mutation control: emptying the cross-subprogram summaries (R) / (W) (rmwAcrossCalls = false — a test-only switch) turns every cross-call negative case back into accepted —
// the rule works through the summaries (a frontend without them silently accepts).
func TestRMWAcrossCallsMutation(t *testing.T) {
	dirs := []string{"rmwx_ret_field", "rmwx_ret_update", "rmwx_ret_atomic", "rmwx_arg_field", "rmwx_arg_update", "rmwx_arg_atomic", "rmwx_transitive",
		"ga_helper_w", "ga_helper_r"} // a global G.Add delta carried across a helper (W) / (R)
	for _, dir := range dirs {
		on, err := Analyze(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		if on.OK() {
			t.Fatalf("%s: must be rejected with the summaries", dir)
		}
		rmwAcrossCalls = false
		off, err := Analyze(filepath.Join("testdata", dir))
		rmwAcrossCalls = true
		if err != nil {
			t.Fatal(err)
		}
		if !off.OK() {
			for _, d := range off.Diagnostics {
				t.Log(d.String())
			}
			t.Errorf("%s: without the summaries it must be accepted (the rule works only through them)", dir)
		}
	}
}

// A global G.Add delta within the same function (direct, or through a local) does not depend on the summaries — it stops with the switch off.
func TestGlobalAddSameFunctionWithoutSummaries(t *testing.T) {
	for _, dir := range []string{"ga_direct", "ga_local"} {
		rmwAcrossCalls = false
		off, err := Analyze(filepath.Join("testdata", dir))
		rmwAcrossCalls = true
		if err != nil {
			t.Fatal(err)
		}
		if off.OK() {
			t.Errorf("%s: the same-function global delta rule must not depend on the summaries", dir)
		}
	}
}

// The summary-off switch is for tests only — no non-test source in the package assigns rmwAcrossCalls.
func TestRMWAcrossCallsSwitchTestOnly(t *testing.T) {
	if !rmwAcrossCalls {
		t.Fatal("rmwAcrossCalls must be true by default")
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
					if id, ok := lhs.(*ast.Ident); ok && id.Name == "rmwAcrossCalls" {
						t.Errorf("%s: rmwAcrossCalls is assigned outside the tests", fset.Position(id.Pos()))
					}
				}
			}
			return true
		})
	}
	if n < 10 {
		t.Fatalf("parsed only %d non-test files", n)
	}
}
