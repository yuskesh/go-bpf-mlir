package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// An fsession program has no result (done).
//
//gobpf:fsession bpf_fentry_test1
func f(ctx *bpf.FsessionContext) int32 {
	return 0
}

func main() {}
