package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The sk_reuseport ctx is read-only (the kernel's sk_reuseport_is_valid_access refuses every write) — there is no write method.
func onSelect(ctx *bpf.SkReuseportContext) bpf.SKAction {
	ctx.SetHash(1)
	return bpf.SKPass
}

func main() {}
