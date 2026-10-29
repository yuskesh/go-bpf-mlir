package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Sock struct {
	_    bpf.Kernel `kernel:"sock"`
	Mark uint32     `kernel:"sk_mark"`
}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	x := bpf.FentryArgInt[uint64](ctx, 0)
	if p := bpf.FentryArg[Sock](ctx, 0); p != nil {
		Out.Update(0, x+uint64(p.Mark))
	}
}

func main() {}
