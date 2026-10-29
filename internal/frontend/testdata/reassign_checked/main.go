package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Counts.Lookup(0); p != nil {
		p = nil
	}
	return bpf.XDPPass
}

func main() {}
