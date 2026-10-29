package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	N uint64 `schema:"n"`
	A uint64 `schema:"a"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		x := uint64(1)
		if bpf.KtimeNs()&1 == 0 {
			x = p.N
		}
		p.N = x + 2
	}
	C.Update(0, 1)
	return bpf.XDPPass
}

func main() {}
