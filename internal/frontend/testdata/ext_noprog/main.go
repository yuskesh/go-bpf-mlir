package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The replacement target must be a non-ext program in the same package (programs of other processes cannot be named).
//
//gobpf:global
func g(x uint32) uint32 { return x + 10 }

func tgt(ctx *bpf.XDPContext) bpf.XDPAction {
	if g(1) > 5 {
		return bpf.XDPDrop
	}
	return bpf.XDPPass
}

//gobpf:ext someone_elses_prog g
func rep(ctx *bpf.ExtContext) uint32 {
	return bpf.ExtArg[uint32](ctx, 0) + 100
}

func main() {}
