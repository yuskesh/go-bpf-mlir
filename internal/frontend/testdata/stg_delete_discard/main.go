package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Sock struct {
	_    bpf.Kernel `kernel:"sock"`
	Mark uint32     `kernel:"sk_mark"`
}

var Socks = bpf.SKStorage[uint64]{}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	if p := bpf.FentryArg[Sock](ctx, 0); p != nil {
		Socks.Delete(p)
	}
}

func main() {}
