package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	fb := bpf.XDPDrop
	return Ports.Redirect(ctx, 0, fb)
}

func main() {}
