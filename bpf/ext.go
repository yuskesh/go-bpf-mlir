package bpf

// ext (freplace) programs (bpf-mlir's ext kind):
//
//	//gobpf:global
//	func g(x uint32) uint32 { return x + 10 }
//
//	func tgt(ctx *bpf.XDPContext) bpf.XDPAction { … g(n) … }
//
//	//gobpf:ext tgt g
//	func repG(ctx *bpf.ExtContext) uint32 {
//		x := bpf.ExtArg[uint32](ctx, 0)
//		return x + 100
//	}
//
// Directive `//gobpf:ext <program> <function>` — `<program>` is a non-ext program in the same package, and `<function>` is a `//gobpf:global` function that `<program>`
// calls. When the ext program is attached with gobpf.AttachExt after load, the calls of `<function>` **inside that program** are replaced by the ext program
// (another program that calls the same function is not replaced). The replacement target must come from the same Load (it cannot attach to another process's program).
// The result type equals `<function>`'s result type, and arguments come from ExtArg (T equals the type of `<function>`'s i-th argument). `<function>` has integer arguments and results only.
// A non-root loader needs CAP_BPF + CAP_PERFMON plus the capability of the replacement target's kind (CAP_NET_ADMIN for xdp). CAP_SYS_ADMIN is not needed (the replacement target's BTF
// comes from cilium's cache of the programs it loaded itself; {bpf, net_admin, perfmon} passed on 7.1.8).

// ExtContext is the context of an ext (BPF_PROG_TYPE_EXT, freplace) program. The result is the result type of the replaced function.
type ExtContext struct{ _ [0]func() }

// ExtArg is eBPF side only: the value of the replaced function's i-th (constant) argument (ebpf.ext.arg). T is the integer type equal to the function's i-th argument type.
func ExtArg[T KprobeInt](ctx *ExtContext, i uint32) T { panic(ebpfOnly("ExtArg")) }
