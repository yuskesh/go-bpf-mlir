package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Select cannot be inside a loop (sk.select_reuseport is not among the ops bpf-mlir allows in an ebpf.loop body).

var Socks = bpf.ReuseportSockArray{MaxEntries: 2}

func onSelect(ctx *bpf.SkReuseportContext) bpf.SKAction {
	for i := uint32(0); i < 2; i++ {
		if st := Socks.Select(ctx, i); st == 0 {
			return bpf.SKPass
		}
	}
	return bpf.SKPass
}

func main() {}
