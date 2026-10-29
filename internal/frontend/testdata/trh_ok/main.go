package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Positive case: a tracepoint event struct (Ret is at 16 through Go's implicit padding — same as the tracefs format), raw_tp args, kretprobe and uretprobe return values.
type GetppidExit struct {
	_   [8]byte
	Nr  int32 `tp:"__syscall_nr"`
	Ret int64 `tp:"ret"`
}

//gobpf:tracepoint syscalls/sys_exit_getppid
func tp(ctx *bpf.TracepointContext[GetppidExit]) {
	Out.Update(0, uint64(ctx.Event().Ret))
	Out.Update(1, uint64(int64(ctx.Event().Nr)))
}

//gobpf:raw_tp sys_enter
func raw(ctx *bpf.RawTPContext) {
	Out.Update(2, bpf.RawTPArg(ctx, 1))
}

//gobpf:kretprobe bpf_fentry_test1
func kret(ctx *bpf.KretprobeContext[int32]) {
	Out.Update(3, uint64(int64(ctx.Ret())))
}

//gobpf:uretprobe cfix greet
func uret(ctx *bpf.UretprobeContext[uint32]) {
	Out.Update(4, uint64(ctx.Ret()))
}

func main() {}
