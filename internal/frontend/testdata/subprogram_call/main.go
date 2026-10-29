package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func helper() {}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	helper()
	return bpf.XDPPass
}

func main() {}
