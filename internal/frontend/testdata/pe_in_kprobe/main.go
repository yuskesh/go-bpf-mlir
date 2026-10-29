package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

var Saved bpf.PerfEventContext

//gobpf:fentry bpf_fentry_test1
func f(ctx *bpf.FentryContext) {
	Out.Update(0, Saved.SamplePeriod())
}

func main() {}
