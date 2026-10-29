package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// p.Hits++ in a helper that takes a packet window and a borrow — GB028 on a shared array (writes in window-and-borrow helpers follow the same rule).
type Rule struct {
	Proto uint32 `schema:"proto"`
	Hits  uint32 `schema:"hits"`
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}

func count(w bpf.Window, p *Rule) uint32 {
	r := uint32(0)
	if uint32(w.U8(23)) == p.Proto {
		p.Hits++
		r = 1
	}
	return r
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(0); p != nil {
			_ = count(w, p)
		}
	}
	return bpf.XDPPass
}

func main() {}
