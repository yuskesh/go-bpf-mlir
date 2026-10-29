package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type R struct {
	N uint64    `schema:"n"`
	H [4]uint32 `schema:"h"`
	W uint16    `schema:"w"`
	_ [6]byte
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

var I = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		bpf.AtomicAdd(&p.H[0], 1)
	}
	return bpf.XDPPass
}

func main() {}
