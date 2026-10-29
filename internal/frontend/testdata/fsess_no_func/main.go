package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The fsession directive is missing.
func f(ctx *bpf.FsessionContext) {
	ctx.SetCookie(1)
}

func main() {}
