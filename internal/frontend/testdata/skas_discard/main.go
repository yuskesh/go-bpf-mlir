package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A statement that discards st and found — GB017.
var Socks = bpf.SockMap{MaxEntries: 4}

func onAssign(ctx *bpf.SkLookupContext) bpf.SKAction {
	Socks.Assign(ctx, 0, 0)
	return bpf.SKPass
}

func main() {}
