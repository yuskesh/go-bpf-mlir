package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// sk_lookup returns SKAction (verdict family sk_action) — CgroupAction is the wrong type.
func onLookup(ctx *bpf.SkLookupContext) bpf.SKAction {
	return bpf.CgroupAllow
}

func main() {}
