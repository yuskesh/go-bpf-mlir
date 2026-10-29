package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The fexit context cannot be passed to a callee (the return value is an attach-dependent read — read it in the caller and pass an integer) — GB013.
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func ret(ctx *bpf.FexitContext[int32]) int32 {
	return ctx.Ret()
}

//gobpf:fexit bpf_fentry_test1 nargs=1
func onExit(ctx *bpf.FexitContext[int32]) {
	Out.Update(0, uint64(ret(ctx)))
}

func main() {}
