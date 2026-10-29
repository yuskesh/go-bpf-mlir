package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf"
)

// RunSyscall runs a syscall program (a function value) once with BPF_PROG_TEST_RUN (it is not attached). ctx is the bytes passed to the program
// (at least as long as the farthest byte the program reads — shorter gives EINVAL from the kernel), retval is the program's return value (u32), and ctxOut is the ctx the kernel
// wrote back after the test run (the same as ctx, since the program does not write ctx). A non-root loader needs CAP_BPF.
func RunSyscall(o *Objects, fn any, ctx []byte) (retval uint32, ctxOut []byte, err error) {
	p, err := o.Program(fn)
	if err != nil {
		return 0, nil, err
	}
	e := o.entryOf(fn)
	if e == nil || e.Kind != "syscall" {
		return 0, nil, fmt.Errorf("gobpf.RunSyscall: takes a syscall program (func f(ctx *bpf.SyscallContext) bpf.SyscallRet)")
	}
	out := make([]byte, len(ctx))
	retval, err = p.Run(&ebpf.RunOptions{Context: ctx, ContextOut: out})
	if err != nil {
		return 0, nil, fmt.Errorf("gobpf.RunSyscall: program %s: %w", e.Symbol, err)
	}
	return retval, out, nil
}
