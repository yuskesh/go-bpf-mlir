package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 8}

type Sock struct {
	_    bpf.Kernel `kernel:"sock"`
	Mark uint32     `kernel:"sk_mark"`
}

// Positive case: every width and sign, earlier arguments left unread (prefix null), mixed with a FentryArg struct.

//gobpf:fentry bpf_fentry_test5
func t5(ctx *bpf.FentryContext) {
	a := bpf.FentryArgInt[uint64](ctx, 0)
	c := bpf.FentryArgInt[int16](ctx, 2)
	d := bpf.FentryArgInt[int32](ctx, 3)
	Out.Update(0, a+uint64(int64(c))+uint64(int64(d)))
}

//gobpf:fentry bpf_fentry_test3
func t3(ctx *bpf.FentryContext) {
	a := bpf.FentryArgInt[uint8](ctx, 0)
	Out.Update(1, uint64(a))
}

//gobpf:fentry bpf_fentry_test4
func t4(ctx *bpf.FentryContext) {
	b := bpf.FentryArgInt[int8](ctx, 1)
	d := bpf.FentryArgInt[uint32](ctx, 3)
	Out.Update(2, uint64(int64(b))+uint64(d))
}

//gobpf:fentry tcp_sendmsg
func send(ctx *bpf.FentryContext) {
	size := bpf.FentryArgInt[uint64](ctx, 2)
	if p := bpf.FentryArg[Sock](ctx, 0); p != nil {
		Out.Update(3, size+uint64(p.Mark))
	}
}

func main() {}
