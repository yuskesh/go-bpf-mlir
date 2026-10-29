package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	c := false
	if p := Out.Lookup(0); p != nil {
		c = *p == 1
	}
	if c {
		return bpf.XDPDrop
	}
	return Ports.Redirect(ctx, 0, bpf.XDPPass)
}

func main() {}
