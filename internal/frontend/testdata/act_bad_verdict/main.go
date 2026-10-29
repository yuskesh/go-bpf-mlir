package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// tc_act's redirect (7) is outside the subset of sched_act verdicts.
func f(ctx *bpf.TCActContext) bpf.TCActAction {
	return bpf.TCActAction(7)
}

func main() {}
