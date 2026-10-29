package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// RemotePort is a be16 uint16 — assigning it to a uint32 variable is a Go type error (the width is never silently widened).
func onLookup(ctx *bpf.SkLookupContext) bpf.SKAction {
	var p uint32 = ctx.RemotePort()
	if p == 7001 {
		return bpf.SKDrop
	}
	return bpf.SKPass
}

func main() {}
