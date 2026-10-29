package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// sk_lookup takes no directive (the type determines the kind).
//
//gobpf:sk_lookup
func onLookup(ctx *bpf.SkLookupContext) bpf.SKAction {
	return bpf.SKPass
}

func main() {}
