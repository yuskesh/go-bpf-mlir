package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The writable buffer exists only on the raw_tp_writable context (the non-writable raw_tp context has no Buffer).
//
//gobpf:raw_tp sys_enter
func onRaw(ctx *bpf.RawTPContext) {
	_ = ctx.Buffer()
}

func main() {}
