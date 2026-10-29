package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The replaced function must be //gobpf:global (the kernel refuses static functions with "Cannot replace static functions").
func g(x uint32) uint32 { return x + 10 }

func tgt(ctx *bpf.XDPContext) bpf.XDPAction {
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
