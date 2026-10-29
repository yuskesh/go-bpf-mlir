package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type OpenatEnter struct {
	_  [8]byte
	Nr int32 `tp:"__syscall_nr"`
}

type Ev struct {
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	Status int64     `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:tracepoint syscalls/sys_enter_openat
func f(ctx *bpf.TracepointContext[OpenatEnter]) {
	_, _ = Names.OutputStr(Ev{}, ctx.Event().Nr)
}

func main() {}
