package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:raw_tp sys_enter
func f(ctx *bpf.RawTPContext) {
	i := uint32(bpf.KtimeNs() & 1)
	Out.Update(0, bpf.RawTPArg(ctx, i))
}

func main() {}
