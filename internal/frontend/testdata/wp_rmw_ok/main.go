package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Control: the return of a helper that reads the window and p is written to a borrow q of another map — not an RMW (not GB028).
type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

type Out struct {
	Last uint32 `schema:"last"`
	_    [4]byte
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}
var Outs = bpf.Array[uint32, Out]{MaxEntries: 4}

func next(w bpf.Window, p *Rule) uint32 {
	return p.Class + uint32(w.U8(23))
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(0); p != nil {
			if q := Outs.Lookup(0); q != nil {
				q.Last = next(w, p)
			}
		}
	}
	return bpf.XDPPass
}

func main() {}
