package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Ports.Redirect(ctx, 0, bpf.XDPPass)
	return bpf.XDPPass
}

func main() {}
