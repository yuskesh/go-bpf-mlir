package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

// A packet window together with a map value pointer was GB013 at first, and is accepted now (positive case — TestWindowAndPtrOK).
func mix(w bpf.Window, p *uint64) uint32 {
	return uint32(w.U8(0)) + uint32(*p)
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if p := Counts.Lookup(0); p != nil {
		if w, ok := ctx.Check(0, 14); ok {
			k = mix(w, p) & 7
		}
	}
	Counts.AtomicAdd(k, 1)
	return bpf.XDPPass
}

func main() {}
