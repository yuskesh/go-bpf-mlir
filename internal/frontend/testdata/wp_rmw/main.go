package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// GB028 provenance: a field of a borrow p of a shared map is written back to p via the return of a helper that reads the window and p — a non-atomic RMW of p.Class.
type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}

func next(w bpf.Window, p *Rule) uint32 {
	return p.Class + uint32(w.U8(23))
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(0); p != nil {
			p.Class = next(w, p)
		}
	}
	return bpf.XDPPass
}

func main() {}
