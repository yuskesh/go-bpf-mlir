package bpf

// usdt programs (bpf-mlir's usdt kind):
//
//	//gobpf:usdt fixture/usfix us:hit      ← the binary path (relative to the package directory, used at generate time only) and the USDT point <provider>:<name>
//	func onHit(ctx *bpf.USDTContext) {
//		i := bpf.ProbeTargetIndex(ctx)     // the point's index (i in the order of the binary's notes)
//		a, st := bpf.USDTArg[int64](ctx, 1)
//		…
//	}
//
// Where an argument lives (register, memory, constant) is chosen per point by the binary's compiler — it is read by looking up the spec map the loader writes from the notes (the compiler's
// `__ebpf_usdt_spec_<program>`) by the point's index. At generate time the binary's notes are read, and the point's presence, whether it has a semaphore, and the number, size and sign
// of the USDTArg arguments are checked (the same check runs before load). A point guarded by a semaphore runs only while it is attached with the loader passing the uprobe ref_ctr_offset.
// Attach with gobpf.AttachUSDT (bpf-mlir's glue livecaps.AttachUSDT; the binary comes from gobpf.Load's WithUprobeTarget). The arch is x86_64 only.

// USDTContext is the context of a usdt program (struct pt_regs). No result (done).
type USDTContext struct{ _ [0]func() }

func (*USDTContext) multiProbe() {} // ProbeTargetIndex is the point's index

// USDTArg is eBPF side only: reads argument n (a constant 1..12) of the USDT point now running as T, and returns the value and the raw status (0 is success; −ENOENT if the point has no
// spec; a failed read of a memory location gives probe_read_user's value; on failure the value is 0). T is int8 to uint64 with the same width and sign as the note's `<±size>@`
// (checked at generate time and before load).
func USDTArg[T KprobeInt](ctx *USDTContext, n int) (T, int64) { panic(ebpfOnly("USDTArg")) }
