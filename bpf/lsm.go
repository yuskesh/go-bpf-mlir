package bpf

// lsm and lsm.s programs (bpf-mlir's lsm and lsm.s kinds).
//
//	//gobpf:lsm socket_create
//	func onCreate(ctx *bpf.LSMContext) bpf.LSMRet {
//		fam := bpf.LSMArgInt[int32](ctx, 0)
//		if fam == 44 && mine() {
//			return bpf.LSMDeny(1) // −EPERM
//		}
//		return bpf.LSMAllow
//	}
//
// The hook is the LSM hook name in the directive `//gobpf:lsm <hook>` (`//gobpf:lsm_s <hook>` — sleepable, the context is LSMSleepableContext)
// (the kernel's bpf_lsm_<hook> — for example socket_create, file_open). **The link applies system-wide** (it attaches to the hook of every process) — filtering (tgid, cgroup id) is
// the writer's responsibility, and a wrong deny condition stops the operations of every process on the host. Hook arguments are read with LSMArg (a struct pointer — it can always be NULL) and
// LSMArgInt (an integer), and their types are checked before load against the target kernel's BTF (requirements farg — gobpf.Load's check). lsm.s with a name that is not a sleepable hook
// is rejected by the kernel at load. Attach with gobpf.AttachLSM; a non-root loader needs CAP_BPF + CAP_PERFMON. If the kernel has no BPF LSM
// (CONFIG_BPF_LSM and bpf in the lsm= list), load or attach stops.
//
// lsm_cgroup (restored once loading became possible with cilium/ebpf):
//
//	//gobpf:lsm_cgroup socket_create
//	func onCreate(ctx *bpf.LSMCgroupContext) bpf.CgroupAction {
//		return bpf.CgroupDeny // socket(2) gets EPERM
//	}
//
// **It runs only at the hooks of tasks in the attached cgroup (and its child cgroups)** (gobpf.AttachCgroup — the kernel's shim filters by cgroup). Hook arguments are not readable
// (gobpf does not expose them — ctx has no methods; bpf-mlir has lsm_cgroup arguments (the companion family trace_lsm_cgroup + farg)), and the return value is CgroupDeny (rejects the operation with EPERM) / CgroupAllow. A void hook is
// rejected by the kernel at load. A non-root loader needs CAP_BPF + CAP_PERFMON.

// LSMCgroupContext is the context of an lsm_cgroup (BPF_LSM_CGROUP) program (no methods). The return value is CgroupAction.
type LSMCgroupContext struct{ _ [0]func() }

// LSMContext is the context of an lsm (BPF_LSM_MAC) program. The return value is LSMRet.
type LSMContext struct{ _ [0]func() }

// LSMSleepableContext is the context of an lsm.s (sleepable lsm — BPF_F_SLEEPABLE) program. The API is the same as LSMContext.
type LSMSleepableContext struct{ _ [0]func() }

// LSMHook is the context type of LSMArg / LSMArgInt (LSMContext or LSMSleepableContext).
type LSMHook interface {
	LSMContext | LSMSleepableContext
}

// LSMRet is the return value of an lsm program (0 allows; a negative value −4095..−1 rejects the operation with −errno). The program returns only constants — LSMAllow or LSMDeny(errno)
// (errno is a constant 1..4095). A value out of range or not constant is stopped by the frontend (the kernel verifier also limits the return value of an int hook to −4095..0).
type LSMRet int32

// LSMAllow allows the operation (0).
const LSMAllow LSMRet = 0

// LSMDeny rejects the operation with errno (−errno — for example LSMDeny(1) is −EPERM). On the eBPF side errno is only a constant 1..4095.
func LSMDeny(errno int32) LSMRet { return LSMRet(-errno) }

// LSMArg is eBPF side only: returns argument i (a constant 0..11) of the lsm hook as a pointer to the kernel's struct T (ebpf.ctx.arg — the same shape as FentryArg).
// **It can always be NULL**, so read it only in the shape `if p := bpf.LSMArg[T](ctx, i); p != nil { … } [else { … }]` (kptr.check).
func LSMArg[T any, C LSMHook](ctx *C, i uint32) *T { panic(ebpfOnly("LSMArg")) }

// LSMArgInt is eBPF side only: the value of the lsm hook's integer argument i (a constant 0..11) (ebpf.ctx.arg — the same shape as FentryArgInt). T is int8 to uint64 with the same width and sign as
// the hook's argument (gobpf.Load's check farg stops a mismatch with a named error). Only the shape `x := bpf.LSMArgInt[T](ctx, i)` at the top level of the program body.
func LSMArgInt[T KprobeInt, C LSMHook](ctx *C, i uint32) T { panic(ebpfOnly("LSMArgInt")) }
