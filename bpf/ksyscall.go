package bpf

// ksyscall programs (bpf-mlir's ksyscall kind):
//
//	//gobpf:ksyscall prctl
//	func onPrctl(ctx *bpf.KsyscallContext) {
//		option := bpf.KsyscallArg[int32](ctx, 1)
//		arg2 := bpf.KsyscallArg[uint64](ctx, 2)
//		…
//	}
//
// A kprobe on the syscall entry; it attaches to the syscall wrapper `__x64_sys_<name>` (the directive names only the syscall). gobpf.AttachKsyscall attaches it to the
// wrapper and checks the name it attached to (cilium v0.22 attaches to the bare name in the second half of the section and fails, so gobpf attaches it itself). Arguments are read
// from the user pt_regs behind the wrapper's pt_regs (the 4th is r10, per the syscall calling convention). Their types are checked before load against the tracefs `sys_enter_<name>` format
// (sysarg; **tracefs is readable only by root**: a non-root Load cannot decide the check and stops). The link applies system-wide (it attaches to the syscalls of every
// process; it only reads, and filtering is the writer's responsibility). The arch is x86_64 only.

// KsyscallContext is the context of a ksyscall program (the wrapper's pt_regs). No result (done).
type KsyscallContext struct{ _ [0]func() }

// KsyscallArg is eBPF side only: the value of syscall argument n (a constant 1..6). T is int8 to uint64 with the same width and sign as the syscall argument (a pointer argument is uint64,
// its value only; what it points to is not read). Only the shape `x := bpf.KsyscallArg[T](ctx, n)` as a top-level statement of the program body.
func KsyscallArg[T KprobeInt](ctx *KsyscallContext, n int) T { panic(ebpfOnly("KsyscallArg")) }
