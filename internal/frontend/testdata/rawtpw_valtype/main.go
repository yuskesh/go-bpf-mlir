package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SetBuffer takes only int32 (the buffer is i32 — other widths are a type error).

var Ctl = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:raw_tp_writable bpf_test_finish
func onFinish(ctx *bpf.RawTPWritableContext) {
	if v := Ctl.Lookup(0); v != nil {
		ctx.SetBuffer(*v)
	}
}

func main() {}
