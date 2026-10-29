package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Variable flags — GB006.
var Socks = bpf.SockMap{MaxEntries: 4}

func onAssign(ctx *bpf.SkLookupContext) bpf.SKAction {
	f := bpf.SkAssignFlags(ctx.LocalPort() & 1)
	_, _ = Socks.Assign(ctx, 0, f)
	return bpf.SKPass
}

func main() {}
