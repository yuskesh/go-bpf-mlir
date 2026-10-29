package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Ports.Set(0, 1)
	return Ports.Redirect(ctx, 0, bpf.XDPPass)
}

func main() {}
