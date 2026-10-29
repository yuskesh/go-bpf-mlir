package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 2}

// Positive case: reading SamplePeriod, mixing with a map and CurrentPidTgid, using the value in a loop (a read inside the loop is GB018 — pe_in_loop).

func onSample(ctx *bpf.PerfEventContext) {
	p := ctx.SamplePeriod()
	if bpf.CurrentPidTgid()>>32 != 0 {
		Out.Update(0, p)
	}
	s := uint64(0)
	for i := uint32(0); i < 2; i++ {
		s += p
	}
	Out.Update(1, s)
}

func main() {}
