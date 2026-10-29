package bpf

// tracepoint, raw_tp, kretprobe and uretprobe (bpf-mlir's tracepoint, raw_tp and kretprobe / uretprobe kinds).

// TracepointContext is the context of a tracepoint (a tracefs event — `<category>/<event>`) program. E is the event record struct the user declares, and
// fields with tag `tp:"<tracefs field name>"` are the readable fields (the schema's fields). Offsets are E's Go layout (the same as amd64 C natural alignment), and
// **the first 8 bytes are the common fields** (not readable from BPF — fill them with `_ [8]byte`). Tagged fields are int8 to int64 / uint8 to uint64 only (match the width and sign to the tracefs format's
// size and signed). Declaration errors (offset, width or sign mismatches — including a forgotten padding) are stopped with a named error before load by gobpf.Load's check (requirements tpfield —
// the target's tracefs format) (generate does not read tracefs — the same source gives the same ELF):
//
//	type GetppidEnter struct {
//		_  [8]byte
//		Nr int32 `tp:"__syscall_nr"`
//	}
//
//	//gobpf:tracepoint syscalls/sys_enter_getppid
//	func onGetppid(ctx *bpf.TracepointContext[GetppidEnter]) { nr := ctx.Event().Nr; … }
//
// The event is a system-wide event — filter (tgid, etc.) in the program. Attach with gobpf.AttachTracepoint (all CPUs — needs root: the tracefs id).
// **Load of an object with a tracepoint program needs root** (the check reads the tracefs format — without root, Load stops for the other programs in the same object too.
// To use raw_tp, kretprobe or uretprobe without root, put them in another package). For syscalls events, ebpf-compile stops on offsets at generate time against
// the kernel struct.
type TracepointContext[E any] struct{ _ [0]func() }

// Event is eBPF side only: the event record. **Only the field selection shape `ctx.Event().F`** (each selection is one ebpf.tp.field read — tagged fields only).
// Only in the program body (not inside a subprogram — bpf-mlir limits tp.field to the program entry).
func (c *TracepointContext[E]) Event() *E { panic(ebpfOnly("TracepointContext.Event")) }

// RawTPContext is the context of a raw_tp (raw tracepoint — `//gobpf:raw_tp <tracepoint>`) program. The arguments are an untyped u64 array (bpf_raw_tracepoint_args).
// Attach with gobpf.AttachRawTP.
type RawTPContext struct{ _ [0]func() }

// RawTPArg is eBPF side only: the raw value of raw_tp argument i (a constant 0 to 11) (ebpf.ctx.field "args"[i]). The type is not checked — an i beyond the number of arguments
// is rejected by the kernel at attach.
func RawTPArg(ctx *RawTPContext, i uint32) uint64 { panic(ebpfOnly("RawTPArg")) }

// KretprobeContext is the context of a kretprobe (`//gobpf:kretprobe <kernel function>`) program. R is the function's return type (a 32 / 64-bit integer — rax's
// raw bits at R's width. **The type is not checked** — the value of a void function has no meaning. Read an 8 / 16-bit return value as 32 bits and convert — part of the subset).
// The arch is x86_64 only. Attach with gobpf.AttachKretprobe.
type KretprobeContext[R RetInt] struct{ _ [0]func() }

// RetInt is the return type R of kretprobe / uretprobe (a 32 / 64-bit integer).
type RetInt interface {
	~int32 | ~int64 | ~uint32 | ~uint64
}

// Ret is eBPF side only: the function's return value (ebpf.probe.retval).
func (c *KretprobeContext[R]) Ret() R { panic(ebpfOnly("KretprobeContext.Ret")) }

// UretprobeContext is the context of a uretprobe (`//gobpf:uretprobe <binary path> <symbol>` — the path rules are the same as uprobe) program. R is the same as
// KretprobeContext. The target is SysV (C / C++) functions only — gobpf.Load's check (uretprobe_abi) stops Go functions. Attach with gobpf.AttachUretprobe.
type UretprobeContext[R RetInt] struct{ _ [0]func() }

// Ret is eBPF side only: the function's return value (ebpf.probe.retval).
func (c *UretprobeContext[R]) Ret() R { panic(ebpfOnly("UretprobeContext.Ret")) }
