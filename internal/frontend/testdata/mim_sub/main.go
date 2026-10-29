package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var A = bpf.ArrayOfMaps[uint32, uint64]{MaxEntries: 2, Inner: bpf.InnerSpec{Kind: bpf.InnerHash, MaxEntries: 4}}

func bump(m *bpf.InnerMap[uint32, uint64]) uint64 {
	m.AtomicAdd(0, 1)
	return 0
}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	if m := A.Lookup(0); m != nil {
		_ = bump(m)
	}
	return bpf.XDPPass
}

func main() {}
