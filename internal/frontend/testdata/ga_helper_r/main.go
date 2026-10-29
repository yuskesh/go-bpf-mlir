package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// (R) across a helper — get returns G's Load and the caller uses it as the delta of G.Add — GB021.
var G = bpf.Global[uint64]{}

func get() uint64 {
	return G.Load() & 0xFF
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	G.Add(get())
	return bpf.XDPPass
}

func main() {}
