package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// p.N++ in a callee that takes an unchecked M.Lookup(k) (maybe_ref) — mapped to the argument's map (a shared array): GB028.
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func bump(p *Rec) uint64 {
	r := uint64(0)
	if p != nil {
		p.N++
		r = 1
	}
	return r
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = bump(R.Lookup(2))
	return bpf.XDPPass
}

func main() {}
