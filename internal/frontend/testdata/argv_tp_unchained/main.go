package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type ExecveEnter struct {
	_    [24]byte
	Argv bpf.UserStrArray `tp:"argv"`
}

type Ev struct {
	Slot   int64     `schema:"slot"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	Status int64     `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:tracepoint syscalls/sys_enter_execve
func f(ctx *bpf.TracepointContext[ExecveEnter]) {
	s1, st1, _ := ctx.Event().Argv.At(1)
	_, _ = Names.OutputStr(Ev{Slot: st1}, s1)
}

func main() {}
