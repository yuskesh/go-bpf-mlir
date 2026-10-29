package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A helper that takes a window and a borrow writes to the borrow — GB013 up to v0.12.0 (borrowed arguments were read-only), accepted since.
type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 16}

func learn(w bpf.Window, p *Rule) uint32 {
	p.Proto = uint32(w.U8(23))
	return p.Class
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(0); p != nil {
			k = learn(w, p)
		}
	}
	Counts.AtomicAdd(k&15, 1)
	return bpf.XDPPass
}

func main() {}
