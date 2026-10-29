package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// (W) across a helper — bump Adds its argument to G and the caller passes G's Load — GB021 at the call.
var G = bpf.Global[uint64]{}

func bump(d uint64) uint64 {
	G.Add(d)
	return d
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = bump(G.Load() & 0xFF)
	return bpf.XDPPass
}

func main() {}
