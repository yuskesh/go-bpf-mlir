package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Key struct {
	A uint32 `schema:"a"`
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Counts.Lookup(7); p != nil {
		Counts.Update(0, *p)
	}
	return bpf.XDPPass
}

func main() {}
