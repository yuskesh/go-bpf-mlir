package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func F(p *uint64) uint64 { return *p }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Counts.Lookup(0); p != nil {
		Counts.Update(1, F(p))
	}
	return bpf.XDPPass
}

func main() {}
