package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Counts.Lookup(0); p != nil {
	} else {
		Counts.Update(1, *p)
	}
	return bpf.XDPPass
}

func main() {}
