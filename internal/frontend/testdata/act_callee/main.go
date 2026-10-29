package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func length(ctx *bpf.TCActContext) uint32 {
	return ctx.Len()
}

func f(ctx *bpf.TCActContext) bpf.TCActAction {
	Out.Update(0, uint64(length(ctx)))
	return bpf.TCActOK
}

func main() {}
