package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Key struct {
	A uint32 `schema:"a"`
}

type Val struct {
	N uint64 `schema:"n"`
}

var H = bpf.Hash[Key, Val]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = H.AddOrInit(Key{A: 1}, Val{N: 1})
	return bpf.XDPPass
}

func main() {}
