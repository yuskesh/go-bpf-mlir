package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Caller condition: the borrowed argument is a local variable outside a checked branch (`p := M.Lookup(k)` stored and passed) — currently GB005.
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
	k := uint32(0)
	p := Rules.Lookup(0)
	if w, ok := ctx.Check(0, 24); ok {
		k = classify(w, p)
	}
	Counts.AtomicAdd(k&15, 1)
	return bpf.XDPPass
}

func main() {}
