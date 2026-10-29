package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	N uint64 `schema:"n"`
	A uint64 `schema:"a"`
}

var P = bpf.PerCPUArray[uint32, Rec]{MaxEntries: 1}
var PI = bpf.PerCPUArray[uint32, uint64]{MaxEntries: 1}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := P.Lookup(0); p != nil {
		p.N += 1
		p.A++
	}
	if q := PI.Lookup(0); q != nil {
		PI.Update(0, *q+1)
	}
	return bpf.XDPPass
}

func main() {}
