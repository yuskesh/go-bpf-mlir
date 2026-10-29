package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var S = bpf.ProgArray{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 1); ok {
		S.TailCall(ctx, uint32(w.U8(0)))
	}
	return bpf.XDPDrop
}

func main() {}
