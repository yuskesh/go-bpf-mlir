package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: sk_lookup — reading Family, Protocol, LocalIP4, LocalPort (i32) and RemotePort (be16 i16), verdicts SKDrop / SKPass.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 2}

func onLookup(ctx *bpf.SkLookupContext) bpf.SKAction {
	Out.Update(0, uint64(ctx.Family())<<32|uint64(ctx.LocalIP4()))
	Out.Update(1, uint64(ctx.RemotePort()))
	if ctx.Protocol() == 6 && ctx.LocalPort() == 7001 {
		return bpf.SKDrop
	}
	return bpf.SKPass
}

func main() {}
