package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var X = bpf.XSKMap{MaxEntries: 4}

func f(ctx *bpf.TCIngressContext) bpf.XDPAction {
	return X.Redirect(ctx, 0, bpf.XDPPass)
}

func main() {}
