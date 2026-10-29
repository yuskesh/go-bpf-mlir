package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// ExtArg's T must be identical to the replaced function's argument type (the kernel compares only argument sizes — gobpf stops on the Go type).
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
func rep(ctx *bpf.ExtContext) uint32 {
	return uint32(bpf.ExtArg[int32](ctx, 0)) + 100
}

func main() {}
