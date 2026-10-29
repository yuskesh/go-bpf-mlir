package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Event struct {
	Seq uint64 `schema:"seq"`
}

var Drops = bpf.Array[uint32, uint64]{MaxEntries: 2}

var Events = bpf.RingBuf[uint64]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Events.Output(1)
	return bpf.XDPPass
}

func main() {}
