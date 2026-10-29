package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Rec struct {
	A uint64 `schema:"a"`
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	var x Rec
	Out.Update(0, x.A)
	return bpf.XDPPass
}

func main() {}
