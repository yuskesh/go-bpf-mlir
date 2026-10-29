package bpf

// fsession programs (bpf-mlir's fsession kind; loading needs cilium/ebpf fsession support, upstream PR #2108):
//
//	//gobpf:fsession bpf_fentry_test1
//	func onSess(ctx *bpf.FsessionContext) {
//		if ctx.IsReturn() {
//			Out.AtomicAdd(0, ctx.Cookie())   // the value written at entry
//		} else {
//			ctx.SetCookie(42)
//		}
//	}
//
// **The same program runs at the kernel function's entry and return** (the BPF_TRACE_FSESSION trampoline — fentry and fexit as a pair). IsReturn tells whether it is running at return now,
// and Cookie / SetCookie are an 8-byte value shared between the entry and return of one call. The hook's arguments are not readable; no result. Attach with gobpf.AttachFsession.
// **The kernel needs fsession** (present in 7.1.8, absent in 6.12 / 6.6; the gobpf.Load check stops on attach_type). A non-root loader needs CAP_BPF + CAP_PERFMON.

// FsessionContext is the context of an fsession (BPF_TRACE_FSESSION) program.
type FsessionContext struct{ _ [0]func() }

// IsReturn reports whether the program is now running at the function's return (kfunc bpf_session_is_return). Only at the top level of the program body (not inside a loop).
func (c *FsessionContext) IsReturn() bool { panic(ebpfOnly("FsessionContext.IsReturn")) }

// Cookie reads the 8-byte value shared between entry and return (what kfunc bpf_session_cookie points to).
func (c *FsessionContext) Cookie() uint64 { panic(ebpfOnly("FsessionContext.Cookie")) }

// SetCookie writes the 8-byte value shared between entry and return.
func (c *FsessionContext) SetCookie(v uint64) { panic(ebpfOnly("FsessionContext.SetCookie")) }
