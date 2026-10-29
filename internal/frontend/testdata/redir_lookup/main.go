package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Ports.Lookup(0); p != nil {
		return bpf.XDPDrop
	}
	return Ports.Redirect(ctx, 0, bpf.XDPPass)
}

func main() {}
