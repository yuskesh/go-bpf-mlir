package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	return Ports.Redirect(ctx, 0, bpf.XDPPass)
}

func g() bpf.XDPAction { return Ports.Redirect(nil, 0, bpf.XDPPass) }

func main() { _ = g() }
