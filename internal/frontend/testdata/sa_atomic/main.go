package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	A uint64 `schema:"a"`
	B uint64 `schema:"b"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

// bump does an AtomicAdd on a field of a borrowed argument (GB013 up to v0.12.0 — accepted since).
func bump(p *Rec) uint64 {
	bpf.AtomicAdd(&p.A, 1)
	return 0
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		_ = bump(p)
	}
	return bpf.XDPPass
}

func main() {}
