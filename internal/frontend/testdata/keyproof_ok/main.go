package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Seed is where the value of Counts[d] is copied (this once wrote Counts[d]'s value to Counts[x>>29] — the range [0, 7] of x>>29 cannot be
// shown to differ from d = 5, so it hits GB028 fail closed. This test is about key proofs for Lookup and Update, not RMW — copy to another
// map and write a constant to Counts[x>>29]; the seven proof comments are unchanged).
var Seed = bpf.Array[uint32, uint64]{MaxEntries: 8}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		x = uint32(w.U8(0))
	}
	a := x & 7
	Counts.AtomicAdd(a, 1) // mask
	Counts.AtomicAdd(x%8, 1)
	b := x
	if b >= 8 {
		b = 7
	}
	Counts.AtomicAdd(b, 1) // clamp
	c := x
	c &= 3
	Counts.AtomicAdd(c+4, 1) // 3 + 4
	for i := range uint32(8) {
		Counts.AtomicAdd(i, 1) // loop variable
	}
	d := uint32(5)
	if p := Counts.Lookup(d); p != nil {
		Seed.Update(0, *p)
	}
	Counts.Update(x>>29, 1)
	return bpf.XDPPass
}

func main() {}
