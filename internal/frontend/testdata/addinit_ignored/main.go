package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Key struct {
	A uint32 `schema:"a"`
}

type Val struct {
	N uint64 `schema:"n"`
}

var H = bpf.Hash[Key, uint64]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	H.AddOrInit(Key{A: 1}, 1)
	return bpf.XDPPass
}

func main() {}
