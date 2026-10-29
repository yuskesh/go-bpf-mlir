package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var S = bpf.ProgArray{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	var keep bpf.Window
	if w, ok := ctx.Check(0, 4); ok {
		keep = w
	}
	S.TailCall(ctx, 0)
	C.Update(0, uint64(keep.U8(0)))
	return bpf.XDPDrop
}

func main() {}
