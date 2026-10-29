package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 14); ok {
		x := uint64(w.U8(0))
		off := uint32(14)
		for range uint32(4) {
			if w2, ok2 := ctx.Check(off, 1); ok2 {
				x += uint64(w2.U8(0))
			} else {
				break
			}
			off++
		}
		C.Update(0, x)
	}
	return bpf.XDPPass
}

func main() {}
