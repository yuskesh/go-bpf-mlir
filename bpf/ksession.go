package bpf

// kprobe_session programs (bpf-mlir's kprobe_session kind):
//
//	//gobpf:kprobe_session bpf_fentry_test1
//	func onSess(ctx *bpf.KprobeSessionContext) bpf.KprobeSessionRet {
//		if ctx.IsReturn() { … ctx.Cookie() … } else { ctx.SetCookie(v) }
//		return bpf.KprobeSessionRun
//	}
//
// Directive `//gobpf:kprobe_session <kernel function>` (one function). Through a kprobe.multi link (fprobe), the same program runs at the function's entry and return;
// IsReturn tells them apart, and Cookie / SetCookie pass 8 bytes between them (the same methods as fsession). **If the entry run returns KprobeSessionSkipReturn (1), the return
// run is skipped** (the return run's return value is not used). The return value must be a constant. Arguments are not readable. The kernel needs BPF_TRACE_KPROBE_SESSION and the kfunc signature
// `bpf_session_is_return(void *ctx)` (7.1.8; on 6.12 / 6.6 the gobpf.Load check stops before load). Attach with gobpf.AttachKprobeSession.
// A non-root loader needs CAP_BPF + CAP_PERFMON.

// KprobeSessionContext is the context of a kprobe_session (BPF_TRACE_KPROBE_SESSION) program. The return value is KprobeSessionRet.
type KprobeSessionContext struct{ _ [0]func() }

// KprobeSessionRet is the return value of a kprobe_session program (constants only — KprobeSessionRun or KprobeSessionSkipReturn).
type KprobeSessionRet int32

// kprobe_session return values: KprobeSessionRun runs the return run, and KprobeSessionSkipReturn (returned from the entry run) skips the return run.
const (
	KprobeSessionRun        KprobeSessionRet = 0
	KprobeSessionSkipReturn KprobeSessionRet = 1
)

// IsReturn is eBPF side only: whether the current run is at the function's return (ebpf.session.is_return).
func (c *KprobeSessionContext) IsReturn() bool { panic(ebpfOnly("KprobeSessionContext.IsReturn")) }

// Cookie is eBPF side only: the 8 bytes the entry run stored with SetCookie (ebpf.session.cookie.load).
func (c *KprobeSessionContext) Cookie() uint64 { panic(ebpfOnly("KprobeSessionContext.Cookie")) }

// SetCookie is eBPF side only: stores 8 bytes to pass to the return run (ebpf.session.cookie.store).
func (c *KprobeSessionContext) SetCookie(v uint64) { panic(ebpfOnly("KprobeSessionContext.SetCookie")) }
