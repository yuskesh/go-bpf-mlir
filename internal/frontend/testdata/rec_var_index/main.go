package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Seen struct {
	Len  uint32    `schema:"len"`
	Hist [2]uint16 `schema:"hist"`
}

var M = bpf.Array[uint32, Seen]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	i := uint32(1)
	if p := M.Lookup(0); p != nil {
		p.Hist[i] = 3
	}
	return bpf.XDPPass
}

func main() {}
