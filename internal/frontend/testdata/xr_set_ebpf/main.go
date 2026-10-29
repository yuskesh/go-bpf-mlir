package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var D = bpf.DevMapHash{MaxEntries: 8}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = D.Set(1, 2)
	return D.Redirect(ctx, 1, bpf.XDPPass)
}

func main() {}
