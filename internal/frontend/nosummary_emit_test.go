package frontend

import (
	"os"
	"path/filepath"
	"testing"
)

// Generates the cross-function negative cases with the summary off (rmwAcrossCalls = false — a test-only switch) and writes the .mlir to GOBPF_EMIT_NOSUMMARY_DIR —
// to feed bpf-mlir's rmwprobe (cross-function shapes) "what a frontend without the summary emits". Skipped without the env.
var crossCallNegatives = []string{
	"rmwx_ret_field", "rmwx_ret_update", "rmwx_ret_atomic", "rmwx_arg_field", "rmwx_arg_update", "rmwx_arg_atomic", "rmwx_transitive", "rmwx_arg_varkey",
	"sa_rmw_ref", "wp_rmw",
	"cw_inc", "cw_add_assign", "cw_self_local", "cw_maybe_inc", "cw_win_rmw", "cw_caller_read", "cw_atomic_arg",
	"ga_helper_w", "ga_helper_r",
}

func TestEmitNoSummaryMLIR(t *testing.T) {
	out := os.Getenv("GOBPF_EMIT_NOSUMMARY_DIR")
	if out == "" {
		t.Skip("GOBPF_EMIT_NOSUMMARY_DIR=<dir> writes the cross-call negatives generated without the summaries")
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, dir := range crossCallNegatives {
		on, err := Analyze(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		rmwAcrossCalls = false
		off, err := Analyze(filepath.Join("testdata", dir))
		rmwAcrossCalls = true
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case on.OK():
			t.Logf("%s: accepted even with the summaries — not a cross-call negative", dir)
		case !off.OK():
			t.Logf("%s: rejected without the summaries too (a same-function rule) — not written", dir)
			for _, d := range off.Diagnostics {
				t.Logf("  %s", d.String())
			}
		default:
			if err := os.WriteFile(filepath.Join(out, dir+".mlir"), off.MLIR, 0o644); err != nil {
				t.Fatal(err)
			}
			t.Logf("%s: written (rejected with the summaries, generated without them)", dir)
		}
	}
}
