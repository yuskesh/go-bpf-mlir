package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var A = bpf.ArrayOfMaps[uint32, uint64]{MaxEntries: 2, Inner: bpf.InnerSpec{Kind: bpf.InnerArray, MaxEntries: 4}}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	if m := A.Lookup(0); m != nil {
		for i := uint32(0); i < 4; i++ {
			m.AtomicAdd(i, 1)
		}
	}
	return bpf.XDPPass
}

func main() {}
