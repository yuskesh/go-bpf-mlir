package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The caller passes the d of a callee's bpf.AtomicAdd(&p.N, d) from a field of the same record (p.M) — GB021 (the read and the add are not one atomic).
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func addN(p *Rec, d uint64) uint64 {
	bpf.AtomicAdd(&p.N, d)
	return d
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		_ = addN(p, p.M)
	}
	return bpf.XDPPass
}

func main() {}
