package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Assign on the user-space side — GB003.
var Socks = bpf.SockMap{MaxEntries: 4}

func onAssign(ctx *bpf.SkLookupContext) bpf.SKAction {
	return bpf.SKPass
}

func main() {
	var ctx *bpf.SkLookupContext
	_, _ = Socks.Assign(ctx, 0, 0)
}
