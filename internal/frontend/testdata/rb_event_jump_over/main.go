package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Event is 109216 bytes — one step over bpf-mlir's branch-range limit (ebpf-compile stops with a positioned error). It fits in the ring (131072).
type Event struct {
	Seq uint64       `schema:"seq"`
	Buf [109208]byte `schema:"buf"`
}

var Events = bpf.RingBuf[Event]{MaxEntries: 131072}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Events.Output(Event{Seq: 1})
	return bpf.XDPPass
}

func main() {}
