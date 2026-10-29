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
	if p := C.Lookup(0); p != nil {
		D.Update(0, *p+1)
		D.AtomicAdd(1, *p)
	}
	R.Update(0, Rec{})
	return bpf.XDPPass
}

func main() {}
