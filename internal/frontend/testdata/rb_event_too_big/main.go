package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Event is 4088 bytes — one step over the boundary (4080) of a 4096 ring.
type Event struct {
	Seq uint64     `schema:"seq"`
	Buf [4080]byte `schema:"buf"`
}

var Events = bpf.RingBuf[Event]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Events.Output(Event{Seq: 1})
	return bpf.XDPPass
}

func main() {}
