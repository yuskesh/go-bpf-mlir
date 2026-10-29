package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	var x bpf.XDPAction
	Out.Update(0, uint64(x))
	return bpf.XDPPass
}

func main() {}
