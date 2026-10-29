package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

func double(x uint32) uint32 {
	return x * 2
}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, uint64(double(1)))
	return bpf.XDPPass
}

// Control: the GB004 shape plus a direct call to the helper double from the user side — double really is reachable from both, so GB003 remains.
func main() {
	progs := []any{Count}
	_ = progs
	_ = double(3)
}
