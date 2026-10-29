package bpf

// UprobeContext is the context of a uprobe program (struct pt_regs). A function whose first parameter has this type and whose preceding doc has the directive
// `//gobpf:uprobe <binary path> <symbol>` becomes a uprobe program:
//
//	//gobpf:uprobe fixture/cfix sum_args
//	func onSum(ctx *bpf.UprobeContext) { a := bpf.UprobeArg[int64](ctx, 1); … }
//
// **The directive's path is used only at generate time** (relative to the package directory — for checking the binary's sha256, the symbol and the DWARF types). The path goes
// into neither the ELF nor the generated files — **the path and PID at run time are loader inputs** (gobpf.Load's WithUprobeTarget and gobpf.AttachUprobe).
// The target is **only functions with the C ABI** (C functions, the C entry of a cgo `//export`): Go functions (whose DWARF compilation unit language is Go) have a different register
// assignment (ABIInternal), so they stop at generate and before load. **Your own binary cannot be the target** — the binary's sha256 goes into the ELF at generate
// time, and the ELF is embedded in this Go binary, so the hash is circular. A uprobe does not fire on inlined calls (only at the symbol's entry).
// The program is x86_64 only and has no verdict (the return value is 0). A non-root loader needs CAP_SYS_ADMIN.
type UprobeContext struct{ _ [0]func() }

// UprobeArg is eBPF side only: reads argument n (a constant 1 to 6 — SysV register passing) of the user function as T (the same rules as KprobeArg — T is in the schema's
// params, and if it differs from the binary's DWARF type, generate and gobpf.Load stop. A program that reads the same n with two types is stopped by the frontend).
func UprobeArg[T KprobeInt](ctx *UprobeContext, n int) T { panic(ebpfOnly("UprobeArg")) }

// UserStr is a pointer to a user string (a uprobe argument — bpf-mlir's !ebpf.user_str). It can be used only as an argument of RingBuf.OutputStr.
type UserStr struct{ _ [0]func() }

// UprobeStr is eBPF side only: argument n as a pointer to a user string (if the DWARF type is not a single-level pointer to an 8-bit char — const char * —
// generate and gobpf.Load stop). It can be written directly **only as the second argument of RingBuf.OutputStr**.
func UprobeStr(ctx *UprobeContext, n int) UserStr { panic(ebpfOnly("UprobeStr")) }

// OutputStr is eBPF side only (uprobe programs): reserves and writes event v, reads the user string s into the exactly one `[N]byte` field with tag `gobpf:"userstr"` in V's record
// (helper probe_read_user_str), and submits. **st is the helper's raw status**: for a non-empty string, the length including NUL;
// for a string longer than N, N (the field holds N−1 characters and NUL); for an unreadable pointer, a negative errno; **for the empty string it differs by kernel (1 on 7.1.8, 0 on 6.12 / 6.6)** —
// test for empty with `st >= 0 && ev.F[0] == 0`. ok is whether it submitted (a failed reservation gives ok = false, st = 0 — not read). **A statement that discards st is
// stopped by the frontend** (GB017 — an explicit `_, ok :=` is accepted). **V also needs exactly one int64 field with tag `gobpf:"userstr_status"`**:
// OutputStr writes st there too — the kernel fills the string field with 0 when it cannot read, so the reader tells failed events apart
// with Status < 0 (a record without it is GB016). Do not write the 2 tagged fields in v's literal (OutputStr writes them).
func (r *RingBuf[V]) OutputStr(v V, s UserStr) (st int64, ok bool) {
	panic(ebpfOnly("RingBuf.OutputStr"))
}

// OutputStrOrDiscard is eBPF side only (uprobe programs): like OutputStr it reserves and writes event v and reads the user string s, but **an event it could not read
// (st < 0) is discarded without submit** (bpf-mlir's conditional discard inside present). The discard condition is only st < 0 — the empty string is
// submitted (the empty st differs by kernel — 1 on 7.1.8, 0 on 6.12 / 6.6). sent is whether it submitted: a failed reservation gives (0, false), a failed read gives (st < 0, false).
// V's record needs exactly one `[N]byte` field with tag `gobpf:"userstr"`. An int64 field with tag `gobpf:"userstr_status"` is not needed
// (if present, st is written — the status of a submitted event is always ≥ 0). A statement that discards st is stopped by the frontend (GB017).
func (r *RingBuf[V]) OutputStrOrDiscard(v V, s UserStr) (st int64, sent bool) {
	panic(ebpfOnly("RingBuf.OutputStrOrDiscard"))
}
