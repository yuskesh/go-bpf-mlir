package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Tasks = bpf.TaskStorage[uint64]{}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	if v := Tasks.Lookup(0); v != nil {
		_ = *v
	}
}

func main() {}
