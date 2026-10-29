package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var opt = true

var A = bpf.Config[uint32]{Optional: opt}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, uint64(A.Value()))
	return bpf.XDPPass
}

func main() {}
