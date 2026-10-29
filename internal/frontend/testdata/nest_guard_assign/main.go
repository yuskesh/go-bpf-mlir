package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pt struct {
	X uint32 `schema:"x"`
	Y uint32 `schema:"y"`
}

type R struct {
	I   uint32 `schema:"i"`
	Pts [2]Pt  `schema:"pts"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		i := p.I
		if i < uint32(len(p.Pts)) {
			i = 0
			p.Pts[i].X = 1
		}
	}
	return bpf.XDPPass
}

func main() {}
