package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A tail call inside a callee that takes the context — a terminal op of the body (now GB023).
var Progs = bpf.ProgArray{MaxEntries: 1}

func jump(ctx *bpf.XDPContext) uint32 {
	Progs.TailCall(ctx, 0)
	return 0
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = jump(ctx)
	return bpf.XDPPass
}

func main() {}
