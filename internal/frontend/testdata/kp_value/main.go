package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Reading an embedded kernel struct as a value (`c := sk.Common`) — GB027.
type Sock struct {
	_      bpf.Kernel `kernel:"sock"`
	Common SockCommon `kernel:"__sk_common"`
}

type SockCommon struct {
	_     bpf.Kernel `kernel:"sock_common"`
	Daddr uint32     `kernel:"skc_daddr"`
}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	if sk := bpf.FentryArg[Sock](ctx, 0); sk != nil {
		c := sk.Common
		Out.Update(0, c.Daddr)
	}
}

func main() {}
