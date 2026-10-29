package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A callee's `d := p.M; bpf.AtomicAdd(&p.N, d)` — GB021 for a delta from the same record through a local variable (borrowedFieldCarrier).
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func addM(p *Rec) uint64 {
	d := p.M
	bpf.AtomicAdd(&p.N, d)
	return d
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		_ = addM(p)
	}
	return bpf.XDPPass
}

func main() {}
