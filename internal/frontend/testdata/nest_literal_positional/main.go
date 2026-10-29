package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pt struct {
	X uint32 `schema:"x"`
	Y uint32 `schema:"y"`
}

type R struct {
	A Pt `schema:"a"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	M.Update(0, R{A: Pt{1, 2}})
	return bpf.XDPPass
}

func main() {}
