package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The lwt packet window is read-only — window writes are xdp only (GB025).
func onXmit(ctx *bpf.LWTXmitContext) bpf.LWTAction {
	if w, ok := ctx.Check(0, 20); ok {
		w.SetU8(8, 1)
	}
	return bpf.LWTOK
}

func main() {}
