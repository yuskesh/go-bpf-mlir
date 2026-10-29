package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Event is 65528 bytes — one step over the boundary (65520) of a 65536 ring (a boundary-match case).
type Event struct {
	Seq uint64      `schema:"seq"`
	Buf [65520]byte `schema:"buf"`
}

var Events = bpf.RingBuf[Event]{MaxEntries: 65536}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Events.Output(Event{Seq: 1})
	return bpf.XDPPass
}

func main() {}
