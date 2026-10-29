package lib

import (
	"github.com/cilium/ebpf/link"

	"github.com/yuskesh/go-bpf-mlir/bpf"
	"github.com/yuskesh/go-bpf-mlir/gobpf"
)

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func helper(x uint64) uint64 { return x + 1 }

func sample(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.AtomicAdd(0, helper(1))
	return bpf.XDPPass
}

// Attach is the entry point for attaching from outside the package (an exported user-side function).
func Attach(objs *gobpf.Objects, ifindex int) (link.Link, error) {
	return gobpf.AttachXDP(objs, sample, ifindex)
}
