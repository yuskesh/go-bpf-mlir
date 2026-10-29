package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: raw_tp_writable — reading and writing the i32 at offset 0 of the writable buffer.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:raw_tp_writable bpf_test_finish
func onFinish(ctx *bpf.RawTPWritableContext) {
	v := ctx.Buffer()
	Out.Update(0, uint64(uint32(v)))
	if v == 0 {
		ctx.SetBuffer(v - 7)
	}
}

func main() {}
