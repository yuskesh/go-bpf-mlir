package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Inside a subprogram's borrowed argument p (map unknown), a Lookup of a map with the same value type — p may point at that value (GB029).
type Rec struct {
	X uint64 `schema:"x"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}

func peek(p *Rec) uint64 {
	v := uint64(0)
	if q := A.Lookup(2); q != nil {
		v = q.X + p.X
	}
	return v
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(0); p != nil {
		_ = peek(p)
	}
	return bpf.XDPPass
}

func main() {}
