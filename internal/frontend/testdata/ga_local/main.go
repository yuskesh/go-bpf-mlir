package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A Load of the same global through a local variable as the delta of G.Add — GB021.
var G = bpf.Global[uint64]{}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	v := G.Load() & 0xFF
	G.Add(v)
	return bpf.XDPPass
}

func main() {}
