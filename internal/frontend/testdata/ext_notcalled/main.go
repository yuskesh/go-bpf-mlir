package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The target program does not call the function (the kernel's "Subprog doesn't exist" — only another program calls it).
//
//gobpf:global
func g(x uint32) uint32 { return x + 10 }

func tgt(ctx *bpf.XDPContext) bpf.XDPAction {
	return bpf.XDPPass
}

func user(ctx *bpf.XDPContext) bpf.XDPAction {
	if g(1) > 5 {
		return bpf.XDPDrop
	}
	return bpf.XDPPass
}

//gobpf:ext tgt g
func rep(ctx *bpf.ExtContext) uint32 {
	return bpf.ExtArg[uint32](ctx, 0) + 100
}

func main() {}
