package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint32(0)
	s := int32(0)
	if w, ok := ctx.Check(0, 14); ok {
		x = w.BE32(0)
		s = int32(w.BE32(4))
	}
	a := x >> 1                      // ≤ 2^31 − 1
	b := a + a + a                   // the sum of upper bounds is 3 * (2^31 − 1) > 2^32 − 1 — it may wrap, so the bound is unknown
	Counts.AtomicAdd(b&7+(x>>31), 1) // 7 + 1 = 8 — at least MaxEntries (cannot be proven)
	Counts.AtomicAdd(b, 1)           // the sum may overflow — unknown
	Counts.AtomicAdd(uint32(s%8), 1) // uint32 after a signed % (may be negative) — unknown
	Counts.AtomicAdd(uint32(s)%8, 1) // % after converting to uint32 — provable
	return bpf.XDPPass
}

func main() {}
