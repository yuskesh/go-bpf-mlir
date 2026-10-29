package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A subprogram that takes the sk_lookup context — GB013 (the sk_lookup context cannot be passed to a subprogram).
var Socks = bpf.SockMap{MaxEntries: 4}

func pick(ctx *bpf.SkLookupContext) int64 {
	st, _ := Socks.Assign(ctx, 0, 0)
	return st
}

func onAssign(ctx *bpf.SkLookupContext) bpf.SKAction {
	_ = pick(ctx)
	return bpf.SKPass
}

func main() {}
