package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// flow_dissector returns FlowAction — CgroupAction is the wrong type.
func dissect(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
	return bpf.CgroupAllow
}

func main() {}
