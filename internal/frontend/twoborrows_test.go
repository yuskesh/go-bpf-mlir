package frontend

import (
	"testing"
)

// TestTwoBorrowsProbe lists the diagnostics of the negative cases and controls (with -v).
func TestTwoBorrowsProbe(t *testing.T) {
	if !testing.Verbose() {
		t.Skip("-v prints the diagnostics of the two-borrow cases")
	}
	for _, dir := range []string{"tb_same_var", "tb_same_const", "tb_param_same", "tb_third", "tb_loop_carry", "tb_lock_other", "tb_rmw", "tb_rmw_ok", "tb_param_nilcheck", "sa_two_ptrs",
		"wp_zero_window", "wp_unchecked_var", "wp_forward", "wp_write_ptr", "wp_tc_write", "wp_rmw", "wp_rmw_ok", "wa_window_and_ptr",
		"cx_kprobe_arg", "cx_uprobe_arg", "cx_fentry_arg", "cx_adjust", "cx_tail", "cx_lock", "cx_not_first", "cx_global", "cx_fexit", "cx_nil_ctx", "cx_redirect", "sub_ctx_param"} {
		res, err := Analyze(caseDir(dir))
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s ok=%v", dir, res.OK())
		for _, d := range res.Diagnostics {
			t.Logf("  %s", d.String())
		}
	}
}
