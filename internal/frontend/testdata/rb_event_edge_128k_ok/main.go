package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Event is 131056 bytes — the largest that fits in a 131072 ring (N - 16 — a boundary-match case, the same value as bpf-mlir's lit test).
type Event struct {
	Seq uint64       `schema:"seq"`
	Buf [131048]byte `schema:"buf"`
}

var Events = bpf.RingBuf[Event]{MaxEntries: 131072}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Events.Output(Event{Seq: 1})
	return bpf.XDPPass
}

func main() {}
