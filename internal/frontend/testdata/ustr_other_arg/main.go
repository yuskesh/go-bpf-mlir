package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	Status int64     `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:ksyscall openat
func f(ctx *bpf.KsyscallContext) {
	_, _ = Names.OutputStr(Ev{}, bpf.UserStr{})
}

func main() {}
