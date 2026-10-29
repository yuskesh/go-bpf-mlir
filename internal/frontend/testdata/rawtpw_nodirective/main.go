package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// raw_tp_writable needs a directive naming the tracepoint to attach to.
func onFinish(ctx *bpf.RawTPWritableContext) {
	ctx.SetBuffer(0)
}

func main() {}
