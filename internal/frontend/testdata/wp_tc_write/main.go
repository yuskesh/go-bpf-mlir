package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Unchanged rule: calling a helper that writes the window and reads a borrow from tc — currently GB013 (packet writes are xdp only).
var Base = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 16}

func stamp(w bpf.Window, b *uint64) uint32 {
	w.SetU8(15, uint8(*b))
	return uint32(*b)
}

func T(ctx *bpf.TCIngressContext) bpf.TCAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 24); ok {
		if b := Base.Lookup(0); b != nil {
			k = stamp(w, b)
		}
	}
	Counts.AtomicAdd(k&15, 1)
	return bpf.TCPass
}

func main() {}
