package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Event struct {
	Seq uint64 `schema:"seq"`
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

var Events = bpf.RingBuf[Event]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint64(0)
	n := uint32(x)
	for i := uint32(0); i < n; i++ {
		x += uint64(i)
	}
	Counts.Update(0, x)
	return bpf.XDPPass
}

func main() {}
