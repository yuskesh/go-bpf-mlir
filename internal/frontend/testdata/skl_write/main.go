package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The sk_lookup ctx is read-only (the kernel's sk_lookup_is_valid_access refuses every write) — there is no write method.
func onLookup(ctx *bpf.SkLookupContext) bpf.SKAction {
	ctx.SetLocalPort(7002)
	return bpf.SKPass
}

func main() {}
