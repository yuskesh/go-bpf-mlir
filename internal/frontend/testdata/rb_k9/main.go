package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	N uint32 `schema:"n"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 1 << 30}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Events.Output(Ev{N: 1}, bpf.CountDropsIn(Drops, 0))
	return bpf.XDPPass
}

var Drops = bpf.Array[uint32, uint64]{MaxEntries: 1}

func main() {}
