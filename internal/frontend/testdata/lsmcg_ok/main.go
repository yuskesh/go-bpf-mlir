package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: lsm_cgroup — no arguments, verdicts CgroupDeny / CgroupAllow (a conditional return).

var (
	Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 2}
)

//gobpf:lsm_cgroup socket_create
func onCreate(ctx *bpf.LSMCgroupContext) bpf.CgroupAction {
	Out.AtomicAdd(1, 1)
	deny := false
	if v := Ctl.Lookup(0); v != nil {
		deny = *v != 0
	}
	if deny {
		Out.AtomicAdd(0, 1)
	}
	if deny {
		return bpf.CgroupDeny
	}
	return bpf.CgroupAllow
}

func main() {}
