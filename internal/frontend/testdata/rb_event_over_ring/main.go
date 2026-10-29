package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Event is 8192 bytes — larger than the ring (4096).
type Event struct {
	Seq uint64     `schema:"seq"`
	Buf [8184]byte `schema:"buf"`
}

var Events = bpf.RingBuf[Event]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Events.Output(Event{Seq: 1})
	return bpf.XDPPass
}

func main() {}
