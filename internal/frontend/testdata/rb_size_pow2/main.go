package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Event struct {
	Seq uint64 `schema:"seq"`
}

var Drops = bpf.Array[uint32, uint64]{MaxEntries: 2}

var Events = bpf.RingBuf[Event]{MaxEntries: 5000}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Events.Output(Event{Seq: 1})
	return bpf.XDPPass
}

func main() {}
