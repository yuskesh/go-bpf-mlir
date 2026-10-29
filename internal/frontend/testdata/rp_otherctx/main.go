package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Select takes only the sk_reuseport context — the sk_lookup context is the wrong type.

var Socks = bpf.ReuseportSockArray{MaxEntries: 2}

func onLookup(ctx *bpf.SkLookupContext) bpf.SKAction {
	Socks.Select(ctx, 0)
	return bpf.SKPass
}

func main() {}
