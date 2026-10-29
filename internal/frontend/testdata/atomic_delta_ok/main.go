package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type R struct {
	N uint64 `schema:"n"`
	G uint64 `schema:"g"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 2}
var Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	d := uint64(1)
	if c := Ctl.Lookup(0); c != nil {
		d = *c
	}
	g := uint64(0)
	if q := M.Lookup(1); q != nil {
		g = q.G
	}
	if p := M.Lookup(0); p != nil {
		bpf.AtomicAdd(&p.N, d)
		bpf.AtomicAdd(&p.N, g+3)
		bpf.AtomicAdd(&p.G, 7)
	}
	return bpf.XDPPass
}

func main() {}
