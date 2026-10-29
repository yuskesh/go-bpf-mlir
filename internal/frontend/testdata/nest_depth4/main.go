package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pt struct {
	X uint32 `schema:"x"`
	Y uint32 `schema:"y"`
}

type L2 struct {
	P Pt `schema:"p"`
}

type L3 struct {
	Q L2 `schema:"q"`
}

type L4 struct {
	R L3 `schema:"r"`
}

var M = bpf.Array[uint32, L4]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		p.R.Q.P.X = 1
	}
	return bpf.XDPPass
}

func main() {}
