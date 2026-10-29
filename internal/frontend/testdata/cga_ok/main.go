package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: cgroup_array's TaskUnder (fentry) and SkbUnder (the tc egress context); the index is a value (it need not be a constant).

var (
	CG  = bpf.CgroupArray{MaxEntries: 8}
	Out = bpf.Array[uint32, int64]{MaxEntries: 2}
)

//gobpf:fentry bpf_fentry_test1
func onTask(ctx *bpf.FentryContext) {
	k := uint32(bpf.CurrentPidTgid() & 7)
	Out.Update(0, CG.TaskUnder(k))
}

func onSkb(ctx *bpf.TCEgressContext) bpf.TCAction {
	if CG.SkbUnder(ctx, 3) == 1 {
		return bpf.TCDrop
	}
	return bpf.TCPass
}

func main() {}
