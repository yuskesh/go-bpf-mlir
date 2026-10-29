package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// Positive case: widths and signs of ksyscall arguments 1 to 6, earlier arguments left unread.

//gobpf:ksyscall openat
func onOpenat(ctx *bpf.KsyscallContext) {
	dfd := bpf.KsyscallArg[int32](ctx, 1)
	name := bpf.KsyscallArg[uint64](ctx, 2)
	flags := bpf.KsyscallArg[int32](ctx, 3)
	mode := bpf.KsyscallArg[uint16](ctx, 4)
	Out.Update(0, uint64(int64(dfd))+name+uint64(int64(flags))+uint64(mode))
}

//gobpf:ksyscall mmap
func onMmap(ctx *bpf.KsyscallContext) {
	off := bpf.KsyscallArg[uint64](ctx, 6)
	Out.Update(1, off)
}

//gobpf:ksyscall getppid
func onGetppid(ctx *bpf.KsyscallContext) {
	Out.AtomicAdd(2, 1)
}

func main() {}
