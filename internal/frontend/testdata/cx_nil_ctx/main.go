package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The context argument is not the caller's context (nil) — GB013.
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func etype(ctx *bpf.XDPContext) uint32 {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = uint32(w.BE16(12))
	}
	return k
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, uint64(etype(nil)))
	return bpf.XDPPass
}

func main() {}
