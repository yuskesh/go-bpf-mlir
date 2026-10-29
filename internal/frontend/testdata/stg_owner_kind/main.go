package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Sock struct {
	_    bpf.Kernel `kernel:"sock"`
	Mark uint32     `kernel:"sk_mark"`
}

var Tasks = bpf.TaskStorage[uint64]{}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Sock](ctx, 0); p != nil {
		if v := Tasks.Get(p, bpf.Create); v != nil {
			_ = *v
		}
	}
}

func main() {}
