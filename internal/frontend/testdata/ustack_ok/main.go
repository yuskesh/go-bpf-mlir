package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// User stacks (IP and build id — uprobe, kprobe, fentry) and every form of kprobe pointer argument.

var Stacks = bpf.StackTrace{MaxEntries: 64, Depth: 16}

var Builds = bpf.StackBuildID{MaxEntries: 64, Depth: 16}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

//gobpf:uprobe cfix sum_args
func onSum(ctx *bpf.UprobeContext) {
	if st := Stacks.UserID(ctx, 0); st >= 0 {
		Out.Update(0, uint64(st))
	}
	if st := Builds.UserIDReuse(ctx, 0); st >= 0 {
		Out.Update(1, uint64(st))
	}
}

//gobpf:kprobe do_sys_poll
func onPoll(ctx *bpf.KprobeContext) {
	ufds := uint64(bpf.KprobeArg[uintptr](ctx, 1))
	Out.Update(2, ufds)
	_ = Stacks.UserIDReuse(ctx, 1)
}

//gobpf:fentry do_sys_poll
func onPollEntry(ctx *bpf.FentryContext) {
	if st := Builds.UserID(ctx, 0); st >= 0 {
		Out.Update(3, uint64(st))
	}
}

func main() {}
