package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stacks = bpf.StackTrace{MaxEntries: 64, Depth: 16}

var Builds = bpf.StackBuildID{MaxEntries: 64, Depth: 16}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = Stacks.UserID(ctx, 0)
	return bpf.XDPPass
}

func main() {}
