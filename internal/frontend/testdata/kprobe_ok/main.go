package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// Positive case: every width and sign, the same n twice with the same type, a program that calls a subprogram.
//
//gobpf:kprobe do_sys_poll
func f(ctx *bpf.KprobeContext) {
	a := bpf.KprobeArg[uint32](ctx, 2)
	b := bpf.KprobeArg[uint32](ctx, 2)
	c := bpf.KprobeArg[int8](ctx, 3)
	d := bpf.KprobeArg[int16](ctx, 4)
	e := bpf.KprobeArg[uint64](ctx, 6)
	Out.Update(0, sum(uint64(a), uint64(b))+uint64(int64(c))+uint64(int64(d))+e)
}

func sum(x, y uint64) uint64 { return x + y }

func main() {}
