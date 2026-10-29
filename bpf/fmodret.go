package bpf

// fmod_ret programs (bpf-mlir's fmod_ret kind):
//
//	//gobpf:fmod_ret bpf_modify_return_test nargs=2
//	func onModRet(ctx *bpf.FmodRetContext) bpf.FmodRet {
//		a := bpf.FmodRetArgInt[int32](ctx, 0)
//		if a == 1 {
//			return bpf.FmodRet(a + 41) // nonzero: skip the original function and make 42 its return value
//		}
//		return 0 // run the original function
//	}
//
// Directive `//gobpf:fmod_ret <kernel function> nargs=<N>` (N is the function's number of arguments — the retsig check at load). The program runs in the trampoline at the kernel function's entry,
// and **returning a nonzero value skips the original function and makes that value its return value** (0 runs the original function). The kernel decides which functions it can attach to
// (functions allowed for error injection, `security_` functions, the kernel's fmodret set — others fail at load with "not modifiable"). The return value may be a computed
// FmodRet (int32) (lsm's LSMRet must be a constant). Arguments are integers only (FmodRetArgInt). Attach with gobpf.AttachFmodRet. A non-root loader needs
// CAP_BPF + CAP_PERFMON (load).

// FmodRetContext is the context of an fmod_ret (BPF_MODIFY_RETURN) program. The return value is FmodRet.
type FmodRetContext struct{ _ [0]func() }

// FmodRet is the return value of an fmod_ret program (0 runs the original function; a nonzero value skips it and returns that value).
type FmodRet int32

// FmodRetArgInt is eBPF side only: the value of integer argument i (a constant 0..11) of the attached function (ebpf.ctx.arg — the same shape as FentryArgInt). T is an integer with the same width and
// sign as the function's argument (the farg check at load). Only `x := bpf.FmodRetArgInt[T](ctx, i)` at the top level of the program body.
func FmodRetArgInt[T KprobeInt](ctx *FmodRetContext, i uint32) T { panic(ebpfOnly("FmodRetArgInt")) }
