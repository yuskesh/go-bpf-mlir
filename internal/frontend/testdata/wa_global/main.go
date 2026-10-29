package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

// A global subprogram cannot take a packet window.
//
//gobpf:global
func proto(w bpf.Window) uint32 {
	return uint32(w.U8(23))
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 24); ok {
		k = proto(w) & 7
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func main() {}
