package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Key struct {
	A uint32 `schema:"a"`
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Counts.Delete(1)
	return bpf.XDPPass
}

func main() {}
