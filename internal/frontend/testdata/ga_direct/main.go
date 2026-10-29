package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The delta of G.Add directly carries a Load of the same global — GB021 (up to v0.12.0 this was generated silently).
var G = bpf.Global[uint64]{}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	G.Add(G.Load() & 0xFF)
	return bpf.XDPPass
}

func main() {}
