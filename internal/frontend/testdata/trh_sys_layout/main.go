package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// sys_enter_kill's pid is at offset 16, 8 bytes in the tracefs format — a declaration written as int32 (offset 12 in the Go layout).
type KillEnter struct {
	_   [8]byte
	Nr  int32 `tp:"__syscall_nr"`
	Pid int32 `tp:"pid"`
}

//gobpf:tracepoint syscalls/sys_enter_kill
func f(ctx *bpf.TracepointContext[KillEnter]) {
	Out.Update(0, uint64(int64(ctx.Event().Pid)))
}

func main() {}
