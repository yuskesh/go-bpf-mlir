package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:perf_event cpu-clock
func onSample(ctx *bpf.PerfEventContext) {
	Out.Update(0, ctx.SamplePeriod())
}

func main() {}
