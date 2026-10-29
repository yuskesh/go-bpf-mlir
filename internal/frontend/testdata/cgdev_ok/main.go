package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: cgroup_device — reading AccessType, Major and Minor; verdicts CgroupDeny / CgroupAllow.

var (
	Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 6}
)

func onDev(ctx *bpf.CgroupDeviceContext) bpf.CgroupAction {
	at, maj, min := ctx.AccessType(), ctx.Major(), ctx.Minor()
	null := maj == 1 && min == 3
	zero := maj == 1 && min == 5
	if null {
		Out.AtomicAdd(0, 1)
	}
	if zero {
		Out.AtomicAdd(1, 1)
	}
	if !null && !zero {
		Out.AtomicAdd(2, 1)
	}
	if null || zero {
		Out.Update(4, uint64(at))
		Out.Update(5, uint64(maj)<<32|uint64(min))
	}
	deny := false
	if v := Ctl.Lookup(0); v != nil {
		deny = *v != 0 && null
	}
	if deny {
		Out.AtomicAdd(3, 1)
	}
	if deny {
		return bpf.CgroupDeny
	}
	return bpf.CgroupAllow
}

func main() {}
