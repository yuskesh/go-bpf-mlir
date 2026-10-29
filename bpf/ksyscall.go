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

// KsyscallStr is eBPF side only: syscall argument n (a constant 1..6) as a pointer to a user string (if the argument is not a single-level `char *` in the tracefs
// `sys_enter_<name>` format, gobpf.Load stops). It can be written directly **only as the second argument of RingBuf.OutputStr / OutputStrOrDiscard**:
//
//	st, ok := Ev.OutputStr(E{…}, bpf.KsyscallStr(ctx, 2))
//
// An argument is read with one type — not with both KsyscallArg and KsyscallStr.
func KsyscallStr(ctx *KsyscallContext, n int) UserStr { panic(ebpfOnly("KsyscallStr")) }

// KsyscallStrArray is eBPF side only: syscall argument n (a constant 1..6) as an array of user string pointers (argv — if the argument is not a two-level
// `char **` in the tracefs `sys_enter_<name>` format, gobpf.Load stops). Its elements are read with UserStrArray.At; it can be written in place as At's receiver
// or bound once to a local variable (`argv := bpf.KsyscallStrArray(ctx, 2)`). An argument is read with one type — not with KsyscallArg, KsyscallStr and KsyscallStrArray together.
func KsyscallStrArray(ctx *KsyscallContext, n int) UserStrArray { panic(ebpfOnly("KsyscallStrArray")) }
