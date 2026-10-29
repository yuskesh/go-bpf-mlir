package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The caller reads p.N and the callee writes its argument to p.N — the callee's (W) target (.N of borrowed argument 1) maps to R[0] at the call site: GB028.
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

func set(p *Rec, n uint64) uint64 {
	p.N = n
	return n
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		x := p.N + 1
		_ = set(p, x)
	}
	return bpf.XDPPass
}

func main() {}
