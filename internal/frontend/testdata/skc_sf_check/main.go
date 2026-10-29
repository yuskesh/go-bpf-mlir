package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

func f(ctx *bpf.SocketFilterContext) bpf.SocketFilterAction {
	if w, ok := ctx.Check(0, 14); ok {
		_ = w
	}
	return bpf.SocketKeep
}

func main() {}
