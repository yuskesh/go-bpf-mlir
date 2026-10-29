package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Unchanged rule: a helper that takes a window and a borrow forwards the window to another subprogram — currently GB013 (window forwarding is a separate question).
type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 16}

func proto(w bpf.Window) uint32 { return uint32(w.U8(23)) }

func classify(w bpf.Window, p *Rule) uint32 {
	return proto(w) ^ p.Class
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(0); p != nil {
			k = classify(w, p)
		}
	}
	Counts.AtomicAdd(k&15, 1)
	return bpf.XDPPass
}

func main() {}
