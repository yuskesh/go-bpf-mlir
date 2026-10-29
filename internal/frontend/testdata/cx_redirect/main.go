package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// redirect_map inside a callee that takes the context — a terminal verdict of the body (program body only).
var Ports = bpf.DevMap{MaxEntries: 1}

func fwd(ctx *bpf.XDPContext) uint32 {
	a := Ports.Redirect(ctx, 0, bpf.XDPPass)
	return uint32(a)
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = fwd(ctx)
	return bpf.XDPPass
}

func main() {}
