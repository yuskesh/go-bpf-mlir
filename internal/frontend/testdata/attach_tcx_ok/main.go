package main

import (
	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func in(ctx *bpf.TCIngressContext) bpf.TCAction {
	Counts.AtomicAdd(0, 1)
	return bpf.TCPass
}

func out(ctx *bpf.TCEgressContext) bpf.TCAction {
	Counts.AtomicAdd(1, 1)
	return bpf.TCPass
}

func main() {
	var objs *gobpf.Objects
	gobpf.AttachTCX(objs, in, 1)
	gobpf.AttachTCX(objs, out, 1)
}
