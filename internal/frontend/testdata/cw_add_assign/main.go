package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A callee's p.N += d on a borrowed argument — GB028 at the call site that passes a shared hash value.
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var H = bpf.Hash[uint32, Rec]{MaxEntries: 16}

func add(p *Rec, d uint64) uint64 {
	p.N += d
	return d
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := H.Lookup(3); p != nil {
		_ = add(p, 2)
	}
	return bpf.XDPPass
}

func main() {}
