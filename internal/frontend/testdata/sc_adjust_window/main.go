package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		a := w.U8(0) == 1
		moved := a && ctx.AdjustHead(4) == 0
		v := uint32(w.U8(1))
		if moved {
			v = 2
		}
		Out.Update(0, v)
	}
	return bpf.XDPPass
}

func main() {}
