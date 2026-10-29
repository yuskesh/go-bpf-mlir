package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Ptr    uint64    `schema:"ptr"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	Status int64     `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:ksyscall openat
func f(ctx *bpf.KsyscallContext) {
	p := bpf.KsyscallArg[uint64](ctx, 2)
	_, _ = Names.OutputStr(Ev{Ptr: p}, bpf.KsyscallStr(ctx, 2))
}

func main() {}
