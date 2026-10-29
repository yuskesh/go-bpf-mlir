package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var X = bpf.XSKMap{MaxEntries: 4}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	X.Redirect(ctx, 0, bpf.XDPPass)
	return bpf.XDPPass
}

func main() {}
