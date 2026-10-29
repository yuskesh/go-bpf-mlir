package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func F(a, b, c, d, e, f uint32) uint32 { return a + b + c + d + e + f }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(F(1, 2, 3, 4, 5, 6)))
	return bpf.XDPPass
}

func main() {}
