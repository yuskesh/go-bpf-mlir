package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 8}

func key(v uint32) uint32 { return v + 1 }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		x = uint32(w.U8(0))
	}
	Counts.AtomicAdd(key(x), 1) // a subprogram's result — the bound is unknown
	b := x
	if b >= 8 {
		b = 7
	}
	b++
	Counts.AtomicAdd(b, 1) // an assignment after the clamp
	c := x
	if c >= 16 {
		c = 15
	}
	Counts.AtomicAdd(c, 1) // the clamp is larger than MaxEntries
	d := uint32(0)
	if x > 3 {
		d = 1
	} else {
		d = x
	}
	Counts.AtomicAdd(d, 1) // only one arm has a bound (unknown after the merge)
	return bpf.XDPPass
}

func main() {}
