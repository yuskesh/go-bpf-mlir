package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func onSample(ctx *bpf.PerfEventContext) {
	s := uint64(0)
	for i := uint32(0); i < 2; i++ {
		s += ctx.SamplePeriod()
	}
	Out.Update(0, s)
}

func main() {}
