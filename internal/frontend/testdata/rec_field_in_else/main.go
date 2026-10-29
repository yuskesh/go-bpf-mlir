package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Seen struct {
	Len  uint32    `schema:"len"`
	Hist [2]uint16 `schema:"hist"`
}

var M = bpf.Array[uint32, Seen]{MaxEntries: 2}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint32(0)
	if p := M.Lookup(0); p != nil {
		x = p.Len
	} else {
		x = p.Len
	}
	M.Update(1, Seen{Len: x})
	return bpf.XDPPass
}

func main() {}
