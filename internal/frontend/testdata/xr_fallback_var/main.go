package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.CPUMap{MaxEntries: 1}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	fb := bpf.XDPPass
	if bpf.KtimeNs() > 0 {
		fb = bpf.XDPDrop
	}
	return C.Redirect(ctx, 0, fb)
}

func main() {}
