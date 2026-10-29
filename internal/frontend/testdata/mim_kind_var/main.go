package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var kind = bpf.InnerHash

var A = bpf.ArrayOfMaps[uint32, uint64]{MaxEntries: 2, Inner: bpf.InnerSpec{Kind: kind, MaxEntries: 4}}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	if m := A.Lookup(0); m != nil {
		m.AtomicAdd(0, 1)
	}
	return bpf.XDPPass
}

func main() {}
