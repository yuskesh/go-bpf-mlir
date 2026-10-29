package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Migration example 3 (v0.4.0 release notes — after): adds to an integer map use M.AtomicAdd (the read and the add are one atomic step).
var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	C.AtomicAdd(0, 1)
	return bpf.XDPPass
}

func main() {}
