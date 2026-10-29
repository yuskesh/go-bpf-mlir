package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:global
func mix(a uint16, b int32) int32 { return int32(a) - b }

func via(a uint16) int32 { return mix(a, 7) }

func tgt(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, uint64(via(3)))
	return bpf.XDPPass
}

//gobpf:ext tgt mix
func rep(ctx *bpf.ExtContext) int32 {
	a := bpf.ExtArg[uint16](ctx, 0)
	b := bpf.ExtArg[int32](ctx, 1)
	r := int32(a) + b
	if a > 10 {
		return r
	}
	return -b
}

func main() {}
