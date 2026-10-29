package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pt struct {
	X uint32 `schema:"x"`
	Y uint32 `schema:"y"`
}

type R struct {
	C [2][2][2]uint8 `schema:"c"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		p.C[0][0][0] = 1
	}
	return bpf.XDPPass
}

func main() {}
