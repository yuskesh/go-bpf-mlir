package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	ow := bpf.XDPDrop
	return Ports.RedirectIf(ctx, true, 0, bpf.XDPPass, ow)
}

func main() {}
