package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	N uint64 `schema:"n"`
	A uint64 `schema:"a"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var D = bpf.Array[uint32, uint64]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(1); p != nil {
		R.Update(1, Rec{N: p.N + 1, A: p.A})
	}
	C.Update(0, 1)
	D.Update(0, 1)
	return bpf.XDPPass
}

func main() {}
