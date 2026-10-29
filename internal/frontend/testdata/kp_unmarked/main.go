package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// An embedded struct field whose type is not a kernel type (no bpf.Kernel mark) — GB027.
type Sock struct {
	_      bpf.Kernel `kernel:"sock"`
	Common SockCommon `kernel:"__sk_common"`
}

type SockCommon struct {
	Daddr uint32 `kernel:"skc_daddr"`
}

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

//gobpf:fentry tcp_sendmsg
func f(ctx *bpf.FentryContext) {
	if sk := bpf.FentryArg[Sock](ctx, 0); sk != nil {
		Out.Update(0, sk.Common.Daddr)
	}
}

func main() {}
