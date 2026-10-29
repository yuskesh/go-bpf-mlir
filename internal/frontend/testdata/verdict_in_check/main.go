package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	c := false
	if p := Out.Lookup(0); p != nil {
		c = *p == 1
	}
	if w, ok := ctx.Check(0, 14); ok {
		if w.U8(0) == 1 && c {
			return bpf.XDPDrop
		}
	}
	return bpf.XDPPass
}

func main() {}
