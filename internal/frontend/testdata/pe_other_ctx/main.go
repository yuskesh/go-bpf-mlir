package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

var Other bpf.PerfEventContext

func onSample(ctx *bpf.PerfEventContext) {
	Out.Update(0, Other.SamplePeriod())
}

func main() {}
