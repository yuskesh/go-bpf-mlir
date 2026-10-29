package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The flow_dissector packet window is read-only — window writes are xdp only (GB025).
func dissect(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
	if w, ok := ctx.Check(14, 20); ok {
		w.SetU8(9, 17)
	}
	return bpf.FlowOK
}

func main() {}
