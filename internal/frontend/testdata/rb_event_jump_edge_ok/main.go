package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Event is 109208 bytes — exactly at bpf-mlir's branch-range limit (accepted). It fits in the ring (131072).
type Event struct {
	Seq uint64       `schema:"seq"`
	Buf [109200]byte `schema:"buf"`
}

var Events = bpf.RingBuf[Event]{MaxEntries: 131072}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Events.Output(Event{Seq: 1})
	return bpf.XDPPass
}

func main() {}
