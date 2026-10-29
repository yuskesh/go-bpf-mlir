package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

// Local is a struct that is not any map's value — a pointer to it cannot be passed to a subprogram (GB013).
type Local struct {
	X uint64
}

func F(p *Local) uint64 { return p.X }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(1, F(nil))
	return bpf.XDPPass
}

func main() {}
