package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Ports = bpf.DevMap{MaxEntries: 4}

var Other = bpf.DevMap{}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	return Other.Redirect(ctx, 0, bpf.XDPPass)
}

func main() {}
