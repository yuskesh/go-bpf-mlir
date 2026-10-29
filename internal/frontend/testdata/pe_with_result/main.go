package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func onSample(ctx *bpf.PerfEventContext) bpf.XDPAction {
	Out.Update(0, ctx.SamplePeriod())
	return bpf.XDPPass
}

func main() {}
