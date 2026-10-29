package bpf

// KernelStr is the type of a `char *` field of a kernel local-type struct (strptr of bpf-mlir's schema kernel_types). Writing the field as
// Filename bpf.KernelStr (with the kernel field name tag `kernel:"filename"`) makes `p.Filename` of a checked kernel pointer a pointer to a kernel string.
// **The value cannot be used directly** (reads, comparisons, assignments and passing are stopped by the frontend — GB027) — it can be written directly **only as the second argument of RingBuf.OutputKernelStr**.
// The path is only a one-level field directly under the kernel pointer (a `char *` inside an embedded struct — for example dentry's d_name.name — and chains of `char *` are not supported).
type KernelStr struct{ _ [0]func() }

// OutputKernelStr is eBPF side only (tracing programs — where a checked kernel pointer exists): reserves and writes event v, reads the kernel string s into the exactly one `[N]byte` (1 ≤ N ≤ 64)
// field of V's record with tag `gobpf:"kernelstr"` (helper probe_read_kernel_str — bpf-mlir's
// ebpf.kernel.read_str), writes st into the exactly one int64 field with tag `gobpf:"kernelstr_status"`, and submits. **st is the helper's raw
// status**: the string length including NUL; a string of N or more bytes gives N (the field holds N−1 characters and NUL); NULL or a user address gives −ERANGE; a read fault gives
// −EFAULT (with a negative status every byte of the field is 0); **an empty string gives 1** (the same on all three kernels — unlike UprobeStr's OutputStr). ok reports whether it submitted
// (a failed reservation gives ok = false and st = 0, without reading). **A statement that discards st is stopped by the frontend** (GB017 — an explicit `_, ok :=` is accepted). The literal of v does not
// write the two tagged fields (OutputKernelStr writes them). The helper needs a loader capability that requires CAP_PERFMON (the requirements' helper row is checked before
// load). The ELF's requirements use format 15 (the schema's strptr rows — from bpf-mlir go/v1.12.0).
func (r *RingBuf[V]) OutputKernelStr(v V, s KernelStr) (st int64, ok bool) {
	panic(ebpfOnly("RingBuf.OutputKernelStr"))
}
