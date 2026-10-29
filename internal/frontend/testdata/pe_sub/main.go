package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func period(ctx *bpf.PerfEventContext) uint64 {
	return ctx.SamplePeriod()
}

func onSample(ctx *bpf.PerfEventContext) {
	Out.Update(0, period(ctx))
}

func main() {}
