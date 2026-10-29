package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

func f(ctx *bpf.SocketFilterContext) bpf.SocketFilterAction {
	return bpf.SocketKeep
}

func main() {
	var c bpf.SocketFilterContext
	_ = c.Len()
}
