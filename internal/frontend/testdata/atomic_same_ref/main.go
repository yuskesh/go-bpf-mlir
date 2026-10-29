package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type R struct {
	N uint64 `schema:"n"`
	G uint64 `schema:"g"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		bpf.AtomicAdd(&p.N, p.G+1)
	}
	return bpf.XDPPass
}

func main() {}
