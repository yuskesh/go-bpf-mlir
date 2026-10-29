package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The raw_tp_writable context cannot be passed to a subprogram (the writable buffer is program body only — bpf-mlir's own entry ctx).
func peek(ctx *bpf.RawTPWritableContext) int32 {
	return ctx.Buffer()
}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:raw_tp_writable bpf_test_finish
func onFinish(ctx *bpf.RawTPWritableContext) {
	Out.Update(0, uint64(uint32(peek(ctx))))
}

func main() {}
