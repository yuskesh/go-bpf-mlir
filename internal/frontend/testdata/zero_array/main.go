package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	var x [4]byte
	Out.Update(0, uint64(x[0]))
	return bpf.XDPPass
}

func main() {}
