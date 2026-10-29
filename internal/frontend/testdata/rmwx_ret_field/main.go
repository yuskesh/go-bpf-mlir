package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	N uint64 `schema:"n"`
	A uint64 `schema:"a"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

// readN carries R[0].N in its return value (R).
func readN() uint64 {
	v := uint64(0)
	if p := R.Lookup(0); p != nil {
		v = p.N
	}
	return v
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	x := readN()
	if p := R.Lookup(0); p != nil {
		p.N = x + 1
	}
	return bpf.XDPPass
}

func main() {}
