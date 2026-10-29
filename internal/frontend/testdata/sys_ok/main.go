package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: syscall — reading 8 / 16 / 32 / 64 bit integers from ctx and a computed SyscallRet return value.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
	x := bpf.SyscallLoad[uint8](ctx, 1)
	y := bpf.SyscallLoad[int16](ctx, 2)
	z := bpf.SyscallLoad[uint32](ctx, 4)
	w := bpf.SyscallLoad[uint64](ctx, 8)
	Out.Update(0, w+uint64(z))
	return bpf.SyscallRet(int32(x) + int32(y))
}

func main() {}
