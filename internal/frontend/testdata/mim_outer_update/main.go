package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var A = bpf.ArrayOfMaps[uint32, uint64]{MaxEntries: 2, Inner: bpf.InnerSpec{Kind: bpf.InnerHash, MaxEntries: 4}}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	A.Update(0, 1)
	return bpf.XDPPass
}

func main() {}
