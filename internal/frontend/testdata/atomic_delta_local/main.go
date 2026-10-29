package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type R struct {
	N uint64 `schema:"n"`
	G uint64 `schema:"g"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 2}
var Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		v := p.G
		bpf.AtomicAdd(&p.N, v)
	}
	return bpf.XDPPass
}

func main() {}
