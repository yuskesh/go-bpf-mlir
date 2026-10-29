package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// flow_keys reads and writes only in the program body (bpf-mlir's ebpf.flow_keys takes only the entry ctx — refused in a static func).
func setProto(ctx *bpf.FlowDissectorContext, p uint8) uint32 {
	ctx.SetIPProto(p)
	return 0
}

func dissect(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
	setProto(ctx, 17)
	return bpf.FlowOK
}

func main() {}
