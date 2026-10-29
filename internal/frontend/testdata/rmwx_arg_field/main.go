package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	N uint64 `schema:"n"`
	A uint64 `schema:"a"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

// writeN writes its argument to R[0].N (W).
func writeN(v uint64) bool {
	ok := false
	if p := R.Lookup(0); p != nil {
		p.N = v
		ok = true
	}
	return ok
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint64(0)
	if p := R.Lookup(0); p != nil {
		x = p.N
	}
	_ = writeN(x + 1)
	return bpf.XDPPass
}

func main() {}
