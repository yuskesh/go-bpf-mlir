package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	return Ports.Redirect(ctx, 0, bpf.XDPAction(4))
}

func main() {}
