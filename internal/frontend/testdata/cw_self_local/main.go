package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A callee's `n := p.N; p.N = n + 1` (a write from its own read through a local variable) — GB028 on a shared array.
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func inc(p *Rec) uint64 {
	n := p.N
	p.N = n + 1
	return n
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(1); p != nil {
		_ = inc(p)
	}
	return bpf.XDPPass
}

func main() {}
