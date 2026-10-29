package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		if w.U8(0) == 1 {
			st := ctx.AdjustHead(4)
			if st == 0 {
				if w2, ok2 := ctx.Check(0, 14); ok2 {
					w2.SetU8(0, 7)
				}
			}
		} else {
			w.SetU8(1, 2)
		}
	}
	return bpf.XDPPass
}

func main() {}
