package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	Status int64     `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

var Seen = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:ksyscall openat
func f(ctx *bpf.KsyscallContext) {
	_, _ = Names.OutputStr(Ev{}, bpf.KsyscallStr(ctx, 2))
	p := bpf.KsyscallArg[uint64](ctx, 2)
	Seen.Update(0, p)
}

func main() {}
