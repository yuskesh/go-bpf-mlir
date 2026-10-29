package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Caller condition: the window argument is not an in_range window from ctx.Check (a zero Window variable) — currently GB013.
type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 16}

func classify(w bpf.Window, p *Rule) uint32 {
	return uint32(w.U8(0)) ^ p.Class
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	var z bpf.Window
	k := uint32(0)
	if p := Rules.Lookup(0); p != nil {
		k = classify(z, p)
	}
	Counts.AtomicAdd(k&15, 1)
	return bpf.XDPPass
}

func main() {}
