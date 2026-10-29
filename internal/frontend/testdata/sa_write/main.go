package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	A uint64 `schema:"a"`
	B uint64 `schema:"b"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

// setA writes to a borrowed argument (GB013 up to v0.12.0 — accepted since).
func setA(p *Rec) uint64 {
	p.A = 5
	return p.B
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		_ = setA(p)
	}
	return bpf.XDPPass
}

func main() {}
