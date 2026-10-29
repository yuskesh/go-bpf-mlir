package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Calls a helper that takes a packet window from inside a (U) loop walk (within the R1 / R2 rules — depth 1, count 4).
func word(w bpf.Window) uint32 {
	return uint32(w.BE16(0))
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	s := uint32(0)
	for i := uint32(0); i < 4; i++ {
		if w, ok := ctx.Check(i*2, 2); ok {
			s += word(w)
		} else {
			break
		}
	}
	Counts.AtomicAdd(0, uint64(s))
	return bpf.XDPPass
}

func main() {}
