package frontend

import (
	"path/filepath"
	"testing"
)

// The reserve size limit — of the kernel __bpf_ringbuf_reserve's two checks, len <= n - 1 decides on an empty ring (measured:
// on a 4096 ring 4080 is reserved and 4088 is always absent — all three kernels). n is a multiple of 8, so this equals size <= n - 16.
func TestRingbufFits(t *testing.T) {
	for _, c := range []struct {
		size, n uint64
		want    bool
	}{
		{4080, 4096, true},
		{4081, 4096, false}, // round_up(4089, 8) = 4096 > 4095
		{4088, 4096, false},
		{4096, 4096, false},
		{8192, 4096, false},
		{1, 4096, true},
		{65520, 65536, true},
		{65528, 65536, false},
		{65528, 131072, true},
	} {
		if got := ringbufFits(c.size, c.n); got != c.want {
			t.Errorf("ringbufFits(%d, %d) = %v, want %v", c.size, c.n, got, c.want)
		}
		if got, alt := ringbufFits(c.size, c.n), c.size <= c.n-16; got != alt {
			t.Errorf("ringbufFits(%d, %d) = %v differs from size <= n - 16 (%v)", c.size, c.n, got, alt)
		}
	}
}

// The boundary itself (4080 / 4096 and 65520 / 65536) is accepted — one below the negative case rb_event_too_big (boundary control).
func TestRingbufEventEdgeOK(t *testing.T) {
	res, err := Analyze(filepath.Join("testdata", "rb_event_edge_ok"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.OK() {
		for _, d := range res.Diagnostics {
			t.Log(d.String())
		}
		t.Fatal("events of MaxEntries - 16 bytes must be accepted (the limit itself)")
	}
}
