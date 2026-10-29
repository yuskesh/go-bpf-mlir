package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pt struct {
	X uint32 `schema:"x"`
	Y uint32 `schema:"y"`
}

type Locked struct {
	L bpf.SpinLock `schema:"l"`
	N uint32       `schema:"n"`
}

type R struct {
	In Locked `schema:"in"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := M.Lookup(0); p != nil {
		p.In.N = 1
	}
	return bpf.XDPPass
}

func main() {}
