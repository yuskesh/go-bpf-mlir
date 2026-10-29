package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint64(0)
	off := uint32(0)
	for range uint32(4) {
		if w, ok := ctx.Check(off, 1); ok {
			b := w.U8(0)
			if b == 0 {
				break
			}
			x += uint64(b)
		}
		off++
	}
	C.Update(0, x)
	return bpf.XDPPass
}

func main() {}
