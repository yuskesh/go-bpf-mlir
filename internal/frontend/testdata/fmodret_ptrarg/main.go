package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// fmod_ret arguments must be integers only (the pointer argument int *b cannot be read with FmodRetArgInt — a type constraint).
//
//gobpf:fmod_ret bpf_modify_return_test nargs=2
func onModRet(ctx *bpf.FmodRetContext) bpf.FmodRet {
	b := bpf.FmodRetArgInt[*int32](ctx, 1)
	_ = b
	return 0
}

func main() {}
