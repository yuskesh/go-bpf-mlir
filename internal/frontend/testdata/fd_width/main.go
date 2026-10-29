package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// flow_keys field widths follow the UAPI table — ip_proto is u8 (passing uint16 is a Go type error; never silently truncated).
func dissect(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
	var p uint16 = 17
	ctx.SetIPProto(p)
	return bpf.FlowOK
}

func main() {}
