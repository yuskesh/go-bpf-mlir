package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The ext result type must be identical to the replaced function's result type (the kernel does not compare return widths — gobpf stops on the Go type).
//
//gobpf:global
func g(x uint32) uint32 { return x + 10 }

func tgt(ctx *bpf.XDPContext) bpf.XDPAction {
	if g(1) > 5 {
		return bpf.XDPDrop
	}
	return bpf.XDPPass
}

//gobpf:ext tgt g
func rep(ctx *bpf.ExtContext) uint64 {
	return uint64(bpf.ExtArg[uint32](ctx, 0)) + 100
}

func main() {}
