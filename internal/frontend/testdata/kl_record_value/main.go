package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	A uint32 `schema:"a"`
}

var Q = bpf.Queue[Ev]{MaxEntries: 4}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	return bpf.XDPPass
}

func main() {}
