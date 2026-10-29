package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Assign inside a loop — GB018.
var Socks = bpf.SockMap{MaxEntries: 4}

func onAssign(ctx *bpf.SkLookupContext) bpf.SKAction {
	for i := uint32(0); i < 2; i++ {
		_, _ = Socks.Assign(ctx, i, 0)
	}
	return bpf.SKPass
}

func main() {}
