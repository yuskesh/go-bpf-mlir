package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// SetCookie takes uint64 — a uint32 variable stops at type checking.
//
//gobpf:fsession bpf_fentry_test1
func f(ctx *bpf.FsessionContext) {
	v := uint32(7)
	ctx.SetCookie(v)
}

func main() {}
