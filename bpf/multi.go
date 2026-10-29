package bpf

// multi probes (bpf-mlir's multi-probe feature):
//
//	//gobpf:kprobe_multi bpf_fentry_test1 bpf_fentry_test2
//	func onEntry(ctx *bpf.KprobeContext) {
//		i := bpf.ProbeTargetIndex(ctx)   // the index in the list (0 is bpf_fentry_test1)
//		a := bpf.KprobeArg[int32](ctx, 1)
//		…
//	}
//
// One link attaches to every listed kernel function (kprobe.multi — fprobe; on a kernel without CONFIG_FPROBE the check before load stops on attach_type).
// The context has the same type as a single kprobe / kretprobe — the directive `//gobpf:kprobe_multi f1 f2 …` / `//gobpf:kretprobe_multi f1 f2 …` decides the kind.
// KprobeArg has the same type for every function (per-function types are outside the subset; the mtarget check before load looks at each function). The pt_regs of kprobe.multi is fprobe's partial
// register set — nothing outside the argument and return-value registers is read. Attach with gobpf.AttachKprobeMulti (the order and indexes of the list follow the mtarget order in the ELF's requirements).

// MultiProbeContext is a context that ProbeTargetIndex accepts (*KprobeContext, *KretprobeContext[R] — the context of a program of a multi kind).
type MultiProbeContext interface{ multiProbe() }

func (*KprobeContext) multiProbe()       {}
func (*KretprobeContext[R]) multiProbe() {}
func (*UprobeContext) multiProbe()       {} // uprobe_multi
func (*UretprobeContext[R]) multiProbe() {} // uretprobe_multi

// ProbeTargetIndex is eBPF side only: the index in the list (0..N−1) of the function a multi-probe program is running for (the cookie the loader set, ebpf.probe.target_index).
// Only in the body of a program of a multi kind (kprobe_multi, kretprobe_multi, uprobe_multi, uretprobe_multi).
//
// uprobe_multi: `//gobpf:uprobe_multi <binary path> s1 s2 …` with *UprobeContext (UprobeArg has the same type for every symbol in the list; UprobeStr is outside),
// and uretprobe_multi with *UretprobeContext[R]. Attach with gobpf.AttachUprobeMulti (the binary comes from Load's WithUprobeTarget).
func ProbeTargetIndex(ctx MultiProbeContext) uint64 { panic(ebpfOnly("ProbeTargetIndex")) }
