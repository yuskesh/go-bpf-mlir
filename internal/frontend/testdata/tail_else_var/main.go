package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var S = bpf.ProgArray{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	a := bpf.XDPPass
	S.TailCallIf(ctx, true, 0, a)
	return bpf.XDPDrop
}

func main() {}
