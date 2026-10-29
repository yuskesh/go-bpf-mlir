package bpf

// KprobeContext is the context of a kprobe program (struct pt_regs). A function whose first parameter has this type and whose preceding doc has the directive
// `//gobpf:kprobe <kernel function>` becomes a kprobe program:
//
//	//gobpf:kprobe do_sys_poll
//	func onPoll(ctx *bpf.KprobeContext) { nfds := bpf.KprobeArg[uint32](ctx, 2); … }
//
// The program runs at the kernel function's entry (x86_64 only). There is no verdict (the return value is 0). The function name is the kernel function itself — gobpf does not switch to an alias
// such as `__x64_` (cilium silently switches to `__x64_X` when attaching to X fails — gobpf.Load checks before load that X exists and the alias does not,
// and gobpf.AttachKprobe checks the actual attach target after attach). A non-root loader needs CAP_BPF + CAP_PERFMON (and kernel.perf_event_paranoid).
type KprobeContext struct{ _ [0]func() }

// KprobeInt is the type of KprobeArg (an integer of 8 to 64 bits).
type KprobeInt interface {
	~int8 | ~int16 | ~int32 | ~int64 | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// KprobeArg is eBPF side only: reads the register of the kprobe function's argument n (a constant 1 to 6 — x86_64 register passing) as T. The value is the low T-width bits of the
// register's raw bits (the upper 32 bits of a 32-bit argument are undefined — x86-64 ABI — so read it as int32 / uint32). T becomes the type in the schema's params,
// and **if it differs from the kernel function's argument type (width and sign), gobpf.Load stops before load** (requirements kprobearg and the target BTF).
// **A pointer argument uses T = uintptr**: only the **in-place conversion** `uint64(bpf.KprobeArg[uintptr](ctx, n))` is
// accepted (a local uintptr variable is stopped by the frontend's rule). The value is the raw 8-byte address and is **not dereferenced** (no read through it — use it as an id or correlation key in a map
// value, an event field or a comparison). Before load, requirements `kprobearg … ptr` checks that the target's argument is a pointer (the pointee type is not checked).
// A program that reads a pointer argument with an integer T is stopped by gobpf.Load with "… is ptr in the target BTF". A program that reads the same n with two types is stopped by the frontend.
func KprobeArg[T KprobeValue](ctx *KprobeContext, n int) T { panic(ebpfOnly("KprobeArg")) }

// KprobeRead is eBPF side only: reads a fixed-width value at byte off (a constant 0 to 4095) behind the kprobe function's argument n (a constant 1 to 6 — **a pointer argument**) as T
// (an integer of 8 to 64 bits) (bpf-mlir's ebpf.kernel.read_scalar, helper probe_read_kernel). The return value is (value, raw status):
// status is 0 or a negative errno (on x86_64, NULL and user-range addresses give −ERANGE (−34), a fault gives −EFAULT (−14)), and **the value on failure is 0** — a value of 0 alone cannot
// tell failure apart, so check status (a statement that silently discards it is stopped by the frontend; an explicit discard `v, _ :=` is accepted). Argument n is a pointer in the schema's params
// (the same declaration as `uint64(KprobeArg[uintptr](ctx, n))` — both may be used together), and before load the target's argument is checked to be a pointer
// (**the pointee layout and address space are not checked** — the user writes off and T from the kernel struct). **Only as a top-level statement of the program body**:
//
//	//gobpf:kprobe do_sys_openat2
//	func onOpen(ctx *bpf.KprobeContext) {
//		flags, st := bpf.KprobeRead[uint64](ctx, 3, 0)   // flags of struct open_how *how (offset 0)
//		…
//	}
//
// kprobe programs only (not usable in uprobe or fentry). x86_64 only.
func KprobeRead[T KprobeInt](ctx *KprobeContext, n int, off int) (T, int64) {
	panic(ebpfOnly("KprobeRead"))
}

// KprobeValue is the type of KprobeArg: an integer of 8 to 64 bits or uintptr (a pointer argument — a value that is not dereferenced).
type KprobeValue interface {
	KprobeInt | ~uintptr
}
