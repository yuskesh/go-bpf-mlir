package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Event struct {
	Seq uint64 `schema:"seq"`
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

var Events = bpf.RingBuf[Event]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint64(0)
	if w, ok := ctx.Check(0, 14); ok {
		for i := range uint32(4) {
			x += uint64(w.U8(0)) + uint64(i)
		}
	}
	Counts.Update(0, x)
	return bpf.XDPPass
}

func main() {}
