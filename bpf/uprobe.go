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
// T = uintptr reads a pointer argument as its raw 8-byte value, only as the in-place conversion `uint64(bpf.UprobeArg[uintptr](ctx, n))` (the value is never
// dereferenced — a key for correlating calls); the argument's DWARF type must be a single-level 8-byte pointer (void *, const char *, a struct pointer — not char **).
// uintptr is accepted in uprobe programs only (not uprobe_multi).
func UprobeArg[T KprobeValue](ctx *UprobeContext, n int) T { panic(ebpfOnly("UprobeArg")) }

// UserBuf is a pointer to a user buffer (bpf-mlir's !ebpf.user_buf) read by length rather than up to a NUL: a uprobe argument (UprobeBuf).
// It can be used only as the second argument of RingBuf.OutputBuf. It is 8 bytes with 8-byte alignment.
type UserBuf struct {
	_ [0]func()
	_ uintptr
}

// UprobeBuf is eBPF side only: argument n as a pointer to a user buffer (if the DWARF type is not a single-level 8-byte pointer — void *, const char *,
// a struct pointer — generate and gobpf.Load stop; char ** and integers stop). It can be written directly **only as the second argument of RingBuf.OutputBuf**,
// in a uprobe program (not uprobe_multi).
func UprobeBuf(ctx *UprobeContext, n int) UserBuf { panic(ebpfOnly("UprobeBuf")) }

// OutputBuf is eBPF side only (uprobe programs): reserves and writes event v, reads min(n, N) bytes of the user buffer b into the exactly one `[N]byte` / `[N]int8`
// field with tag `gobpf:"userbuf"` in V's record (N 1..8192 — helper probe_read_user, called once), and submits. **The count is clamped as a signed value**:
// cnt = max(0, min(n, N)) — a negative n reads 0 bytes. The whole field is zeroed before the read, so the bytes after cnt are 0 and **a failed read leaves the
// whole field 0**. **st is the helper's raw status** (0, or a negative errno when the buffer is unreadable) and **cnt is the clamped requested count, not the number
// of bytes read** — a read of 0 bytes gives st = 0 even for an unreadable pointer. n is int64: convert a narrower length argument in place
// (`int64(bpf.UprobeArg[int32](ctx, 3))` sign-extends, `int64(bpf.UprobeArg[uint32](ctx, 3))` zero-extends — Go's conversion decides).
// ok is whether it submitted (a failed reservation gives (0, 0, false) — not read). **A statement that discards st is stopped by the frontend** (GB017).
// **V also needs exactly one int64 field with tag `gobpf:"userbuf_status"` and exactly one int32 field with tag `gobpf:"userbuf_len"`**: OutputBuf writes st and cnt there —
// a reader tells failed events apart with Status < 0 and reads the first Len bytes of the field. Do not write the 3 tagged fields in v's literal (OutputBuf writes them).
// Not inside loops.
func (r *RingBuf[V]) OutputBuf(v V, b UserBuf, n int64) (st int64, cnt int32, ok bool) {
	panic(ebpfOnly("RingBuf.OutputBuf"))
}

// UserStr is a pointer to a user string (bpf-mlir's !ebpf.user_str): a uprobe argument (UprobeStr), a ksyscall argument (KsyscallStr), a tracepoint event field
// of this type (`F bpf.UserStr` with tag `tp:"<name>"` — a `char *` field of the tracefs format) or an element of a UserStrArray (the s of UserStrArray.At).
// It can be used only as the second argument of RingBuf.OutputStr / OutputStrOrDiscard.
// It is 8 bytes with 8-byte alignment (the size of the pointer — so a tracepoint event struct has the C layout).
type UserStr struct {
	_ [0]func()
	_ uintptr
}

// UserStrArray is an array of user string pointers (bpf-mlir's !ebpf.user_str_array — argv, a `char **`): a ksyscall argument (KsyscallStrArray) or a tracepoint event field
// of this type (`F bpf.UserStrArray` with tag `tp:"<name>"` — a `char **` field of the tracefs format). Its elements are read only with At. It is 8 bytes with 8-byte alignment.
type UserStrArray struct {
	_ [0]func()
	_ uintptr
}

// At is eBPF side only: element i (a constant 0..19) of the array — s is the element's user string pointer, status is the raw status of reading the 8-byte slot
// (helper probe_read_user: 0, or a negative errno when the slot is unreadable) and present is whether the slot was read and is not NULL (s is a NULL pointer when present is false).
// Only the shape `s, st, ok := a.At(i)`; s can be used only as the second argument of RingBuf.OutputStr / OutputStrOrDiscard (reading a NULL s gives a negative status).
// **The frontend enforces the chain**: At(i) with i > 0 is accepted only inside the body of `if ok {` where ok is At(i−1)'s present on the same array — an array ends at its
// first NULL, and the slots after it are not part of it (after argv's NULL come envp's strings). At most the first 20 elements are readable: 20 present elements do not mean
// the array has only 20. Not inside loops or subprograms.
func (a UserStrArray) At(i int) (s UserStr, status int64, present bool) {
	panic(ebpfOnly("UserStrArray.At"))
}

// UprobeStr is eBPF side only: argument n as a pointer to a user string (if the DWARF type is not a single-level pointer to an 8-bit char — const char * —
// generate and gobpf.Load stop). It can be written directly **only as the second argument of RingBuf.OutputStr**.
func UprobeStr(ctx *UprobeContext, n int) UserStr { panic(ebpfOnly("UprobeStr")) }

// OutputStr is eBPF side only (uprobe, tracepoint and ksyscall programs): reserves and writes event v, reads the user string s into the exactly one `[N]byte` field with tag `gobpf:"userstr"` in V's record
// (helper probe_read_user_str), and submits. **st is the helper's raw status**: for a non-empty string, the length including NUL;
// for a string longer than N, N (the field holds N−1 characters and NUL); for an unreadable pointer, a negative errno; **for the empty string it differs by kernel (1 on 7.1.8, 0 on 6.12 / 6.6)** —
// test for empty with `st >= 0 && ev.F[0] == 0`. ok is whether it submitted (a failed reservation gives ok = false, st = 0 — not read). **A statement that discards st is
// stopped by the frontend** (GB017 — an explicit `_, ok :=` is accepted). **V also needs exactly one int64 field with tag `gobpf:"userstr_status"`**:
// OutputStr writes st there too — the kernel fills the string field with 0 when it cannot read, so the reader tells failed events apart
// with Status < 0 (a record without it is GB016). Do not write the 2 tagged fields in v's literal (OutputStr writes them).
func (r *RingBuf[V]) OutputStr(v V, s UserStr) (st int64, ok bool) {
	panic(ebpfOnly("RingBuf.OutputStr"))
}

// OutputStrOrDiscard is eBPF side only (uprobe, tracepoint and ksyscall programs): like OutputStr it reserves and writes event v and reads the user string s, but **an event it could not read
// (st < 0) is discarded without submit** (bpf-mlir's conditional discard inside present). The discard condition is only st < 0 — the empty string is
// submitted (the empty st differs by kernel — 1 on 7.1.8, 0 on 6.12 / 6.6). sent is whether it submitted: a failed reservation gives (0, false), a failed read gives (st < 0, false).
// V's record needs exactly one `[N]byte` field with tag `gobpf:"userstr"`. An int64 field with tag `gobpf:"userstr_status"` is not needed
// (if present, st is written — the status of a submitted event is always ≥ 0). A statement that discards st is stopped by the frontend (GB017).
func (r *RingBuf[V]) OutputStrOrDiscard(v V, s UserStr) (st int64, sent bool) {
	panic(ebpfOnly("RingBuf.OutputStrOrDiscard"))
}
