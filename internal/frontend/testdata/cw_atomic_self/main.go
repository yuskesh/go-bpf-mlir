package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// bpf.AtomicAdd(&p.N, p.M) inside a callee — the lowerer's GB021 (a delta from a field of the same record) also applies to a borrowed argument.
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func addM(p *Rec) uint64 {
	bpf.AtomicAdd(&p.N, p.M)
	return 0
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		_ = addM(p)
	}
	return bpf.XDPPass
}

func main() {}
