package frontend

import (
	"path/filepath"
	"testing"
)

// Required: the callee write summary ((W) with refParam, refRMW) sits under the cross-subprogram summary switch rmwAcrossCalls — setting it false
// turns every call-site negative case (the shapes through arguments) back into accepted. A same-record delta inside the callee (the local shape) is the lowerer's check, outside the switch.
func TestCalleeWriteSummaryMutation(t *testing.T) {
	for _, dir := range []string{"cw_inc", "cw_add_assign", "cw_self_local", "cw_maybe_inc", "cw_win_rmw", "cw_caller_read", "cw_atomic_arg"} {
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
	for _, dir := range []string{"cw_atomic_self", "cw_atomic_local"} {
		rmwAcrossCalls = false
		off, err := Analyze(filepath.Join("testdata", dir))
		rmwAcrossCalls = true
		if err != nil {
			t.Fatal(err)
		}
		if off.OK() {
			t.Errorf("%s: the callee's own delta rule (lowerer GB021) must not depend on the summaries", dir)
		}
	}
}
