package frontend

import (
	"path/filepath"
	"strings"
	"testing"
)

// Positive case for packet window arguments — the callee takes a `!ebpf.pkt_window<N>` argument of a static ebpf.func, the caller passes an in_range window with ebpf.call
// (the same shape as bpf-mlir's kernel/winarg). Reading helpers from xdp and tc, a writing helper from xdp.
func TestWindowArgsOK(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "wa_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("wa_ok must generate")
	}
	mlir := string(res.MLIR)
	for _, want := range []string{
		`ebpf.func @keyLong "static" (!ebpf.pkt_window<24>) -> i32`,
		`ebpf.func @keyShort "static" (!ebpf.pkt_window<14>) -> i32`,
		`ebpf.func @swapMAC "static" (!ebpf.pkt_window<24>) -> i32`,
		`= ebpf.packet.window_load %a0[12] : !ebpf.pkt_window<24> -> i16`,
		`ebpf.packet.store %a0[0], `,
		`= ebpf.call @keyLong(`,
		`: (!ebpf.pkt_window<24>) -> i32`,
	} {
		if !strings.Contains(mlir, want) {
			t.Errorf("generated .mlir lacks %q", want)
		}
	}
}

// Using a program function as a value (GB004) used to walk its body as user-side reachable and cascade GB003 onto helpers.
// GB003 is decided by reachability that skips bodies of already-reported functions — the cascade is gone (fn_value_slice), and GB003 remains for a helper truly reachable from both (control).
func TestNoGB003CascadeAfterGB004(t *testing.T) {
	codes := func(dir string) map[Code][]string {
		res, err := Analyze(filepath.Join("testdata", dir))
		if err != nil {
			t.Fatal(err)
		}
		out := map[Code][]string{}
		for _, d := range res.Diagnostics {
			out[d.Code] = append(out[d.Code], d.Msg)
		}
		return out
	}
	c := codes("fn_value_slice")
	if len(c[GB004UnknownEdge]) == 0 {
		t.Errorf("fn_value_slice: want GB004 for the program function used as a value, got %v", c)
	}
	if len(c[GB003CrossDomainUse]) != 0 {
		t.Errorf("fn_value_slice: GB003 cascaded after GB004: %v", c[GB003CrossDomainUse])
	}
	s := codes("fn_value_slice_shared")
	found := false
	for _, m := range s[GB003CrossDomainUse] {
		if strings.Contains(m, "double") {
			found = true
		}
	}
	if len(s[GB004UnknownEdge]) == 0 || !found {
		t.Errorf("fn_value_slice_shared (control): want GB004 and a GB003 naming double, got %v", s)
	}
}
