package bpf

// syscall programs (bpf-mlir's syscall kind):
//
//	func onSys(ctx *bpf.SyscallContext) bpf.SyscallRet {
//		a := bpf.SyscallLoad[uint32](ctx, 0)
//		b := bpf.SyscallLoad[uint32](ctx, 4)
//		return bpf.SyscallRet(a*3 - b)
//	}
//
// There is no directive (the type decides the kind). **It is not attached** — user space calls BPF_PROG_TEST_RUN with gobpf.RunSyscall, and ctx is the byte slice it passes.
// ctx is read with SyscallLoad (a constant off — a multiple of T's width, off + width ≤ 65535), and the return value is a computed SyscallRet (the test run's retval). bpf() is limited to the 3 cmds
// without pointers (SysBpf) plus SysClose; there are no ctx writes and no kfuncs. The ctx passed must be at least as long as the farthest byte the program reads (if shorter,
// the test run gives EINVAL). A non-root loader needs CAP_BPF (a program that uses SysBpf also needs CAP_PERFMON).

// SyscallContext is the context of a syscall (BPF_PROG_TYPE_SYSCALL) program (the user's byte slice). The return value is SyscallRet.
type SyscallContext struct{ _ [0]func() }

// SyscallRet is the return value of a syscall program (the test run's retval — passed to the user as a u32).
type SyscallRet int32

// SyscallLoad is eBPF side only: reads T (an integer of 8 to 64 bits, little endian) at off of the ctx byte slice (ebpf.ctx.load). off is a constant, a multiple of T's
// width, and off + width ≤ 65535.
func SyscallLoad[T KprobeInt](ctx *SyscallContext, off uint32) T { panic(ebpfOnly("SyscallLoad")) }

// SysBpfCmd is the cmd of SysBpf (the same values as the UAPI enum bpf_cmd — only the 3 whose attr has no pointer fields).
type SysBpfCmd uint32

// SysBpf cmds: SysBpfMapCreate (BPF_MAP_CREATE), SysBpfMapGetFdByID (BPF_MAP_GET_FD_BY_ID — −EPERM for a loader without CAP_SYS_ADMIN),
// SysBpfMapFreeze (BPF_MAP_FREEZE — a second freeze of a frozen map gives −EPERM).
const (
	SysBpfMapCreate    SysBpfCmd = 0
	SysBpfMapGetFdByID SysBpfCmd = 14
	SysBpfMapFreeze    SysBpfCmd = 22
)

// SysBpf is eBPF side only (a top-level statement of a syscall program body, `st := bpf.SysBpf(ctx, cmd, attr)` — bpf-mlir's ebpf.sys.bpf):
// calls bpf(cmd, &attr, sizeof attr) from inside the kernel with helper bpf_sys_bpf and returns the raw status (map_create / map_get_fd_by_id give a new fd —
// it goes into **the fd table of the process that called the test run**, and the caller closes it; map_freeze gives 0; failure gives a negative errno). attr is a composite literal of a named
// struct in this package (a record). **The attr layout is the user's responsibility** — whether the field order matches the cmd's struct in union bpf_attr is
// checked by neither the frontend nor the compiler (a wrong order silently becomes a different attr and gives a different status or a different map). **Compile stops only on size** —
// if the record's size exceeds the offset of the cmd struct's first pointer field (map_create 80, map_freeze 8, map_get_fd_by_id 16 — bpf-mlir's
// SysBpfAttr.def), ebpf-compile stops with the Go position (because the kernel reads attr's pointer fields as kernel pointers).
// cmd is a constant. A statement that discards st is stopped by the frontend (GB017 — `_ =` is accepted). The helper needs a loader capability of CAP_PERFMON.
func SysBpf(ctx *SyscallContext, cmd SysBpfCmd, attr any) int64 { panic(ebpfOnly("SysBpf")) }

// SysClose is eBPF side only (a top-level statement of a syscall program body): closes fd in the fd table of the process that called the test run with helper bpf_sys_close,
// and returns the raw status (0; −EBADF for a missing fd).
func SysClose(ctx *SyscallContext, fd int32) int64 { panic(ebpfOnly("SysClose")) }
