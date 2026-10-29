package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pt struct {
	X uint32 `schema:"x"`
	Y uint32 `schema:"y"`
}

type R struct {
	Pts [2]Pt `schema:"pts"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		p.Pts[1].X = p.Pts[0].Y
		p.Pts[1] = p.Pts[0]
	}
	return bpf.XDPPass
}

func main() {}
