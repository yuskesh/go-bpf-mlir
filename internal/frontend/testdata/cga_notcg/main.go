package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// TaskUnder is only on cgroup_array (Array has no TaskUnder — a type error).

var A = bpf.Array[uint32, uint64]{MaxEntries: 4}

//gobpf:fentry bpf_fentry_test1
func onTask(ctx *bpf.FentryContext) {
	_ = A.TaskUnder(0)
}

func main() {}
