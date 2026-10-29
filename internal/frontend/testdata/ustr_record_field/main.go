package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A bpf.UserStr is a tracepoint event field or a ksyscall argument, never a field of a map or ring buffer record.
type Ev struct {
	Seq  uint64      `schema:"seq"`
	Name bpf.UserStr `schema:"name"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Events.Output(Ev{Seq: 1})
	return bpf.XDPPass
}

func main() {}
