package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

// mark writes to the packet window — calling it from a TC program is GB013 (packet writes are xdp only).
func mark(w bpf.Window) uint32 {
	w.SetU8(0, 0xff)
	return 1
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		_ = mark(w)
	}
	return bpf.XDPPass
}

func Q(ctx *bpf.TCIngressContext) bpf.TCAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = mark(w)
	}
	Counts.AtomicAdd(k, 1)
	return bpf.TCPass
}

func main() {}
