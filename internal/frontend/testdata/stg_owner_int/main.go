package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Tasks = bpf.TaskStorage[uint64]{}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	owner := uint32(7)
	if v := Tasks.Get(owner, bpf.Create); v != nil {
		_ = *v
	}
}

func main() {}
