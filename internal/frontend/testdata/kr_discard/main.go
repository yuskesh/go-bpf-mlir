package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

//gobpf:kprobe do_sys_openat2
func f(ctx *bpf.KprobeContext) {
	bpf.KprobeRead[uint64](ctx, 3, 0)
}

func main() {}
