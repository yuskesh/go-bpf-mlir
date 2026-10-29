package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A callee's p.N++ on a borrowed argument — GB028 at the call site that passes a shared array value (the per-CPU control is cw_ok).
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func bump(p *Rec) uint64 {
	p.N++
	return p.M
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		_ = bump(p)
	}
	return bpf.XDPPass
}

func main() {}
