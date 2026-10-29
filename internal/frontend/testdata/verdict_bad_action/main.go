package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	c := false
	if p := Out.Lookup(0); p != nil {
		c = *p == 1
	}
	if c {
		return bpf.XDPAction(7)
	}
	return bpf.XDPPass
}

func main() {}
