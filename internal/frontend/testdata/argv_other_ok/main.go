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
	envp := bpf.KsyscallStrArray(ctx, 3)
	_, _, ok0 := envp.At(0)
	if ok0 {
		s1, st1, _ := argv.At(1)
		_, _ = Names.OutputStr(Ev{Slot: st1}, s1)
	}
}

func main() {}
