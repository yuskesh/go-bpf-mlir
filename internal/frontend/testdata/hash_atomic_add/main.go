package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Key struct {
	A uint32 `schema:"a"`
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

var H = bpf.Hash[uint32, uint64]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	H.AtomicAdd(1, 1)
	return bpf.XDPPass
}

func main() {}
