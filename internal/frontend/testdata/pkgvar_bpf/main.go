package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func G(x uint32) uint32 { return x + 1 }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(G(1)))
	return bpf.XDPPass
}

var hook = G

func main() { _ = hook }
