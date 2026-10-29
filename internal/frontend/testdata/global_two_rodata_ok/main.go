package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var A = bpf.Config[uint32]{}
var B = bpf.Config[uint32]{}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, uint64(A.Value()+B.Value()))
	return bpf.XDPPass
}

func main() {}
