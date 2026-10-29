package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Slot   int64     `schema:"slot"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	Status int64     `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:ksyscall execve
func f(ctx *bpf.KsyscallContext) {
	argv := bpf.KsyscallStrArray(ctx, 2)
	b := argv
	s, st, _ := b.At(0)
	_, _ = Names.OutputStr(Ev{Slot: st}, s)
}

func main() {}
