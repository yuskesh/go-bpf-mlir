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
	s0, st0, ok0 := argv.At(0)
	_, _ = Names.OutputStr(Ev{Slot: st0}, s0)
	if ok0 {
		s2, st2, _ := argv.At(2)
		_, _ = Names.OutputStr(Ev{Slot: st2}, s2)
	}
}

func main() {}
