package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Writable buffer reads and writes cannot be inside a loop (not measured in bpf-mlir — do them before the loop).

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:raw_tp_writable bpf_test_finish
func onFinish(ctx *bpf.RawTPWritableContext) {
	for i := uint32(0); i < 2; i++ {
		Out.Update(0, uint64(uint32(ctx.Buffer())))
	}
}

func main() {}
