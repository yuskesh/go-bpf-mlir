package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Positive case: widths 1 / 2 / 4 / 8, sign, offsets 0 and 4095, two reads of the same n, a `_` status, mixed with a KprobeArg[uintptr] value.
//
//gobpf:kprobe do_sys_openat2
func f(ctx *bpf.KprobeContext) {
	flags, st := bpf.KprobeRead[uint64](ctx, 3, 0)
	mode, st2 := bpf.KprobeRead[uint64](ctx, 3, 8)
	b, _ := bpf.KprobeRead[int8](ctx, 3, 4095)
	h, sth := bpf.KprobeRead[uint16](ctx, 3, 16)
	w, stw := bpf.KprobeRead[int32](ctx, 2, 0)
	Out.Update(0, flags)
	Out.Update(1, uint64(st))
	Out.Update(2, mode)
	Out.Update(3, uint64(st2))
	Out.Update(4, uint64(int64(b)))
	Out.Update(5, uint64(h)+uint64(sth))
	Out.Update(6, uint64(int64(w))+uint64(stw))
	Out.Update(7, uint64(bpf.KprobeArg[uintptr](ctx, 3)))
}

func main() {}
