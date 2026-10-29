package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var S = bpf.ProgArray{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	S.TailCall(ctx, 0)
	C.AtomicAdd(0, 1)
	S.TailCall(ctx, 1)
	return bpf.XDPDrop
}

func main() {}
