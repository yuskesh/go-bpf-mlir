package bpf

// raw_tp_writable programs (bpf-mlir's raw_tp_writable kind):
//
//	//gobpf:raw_tp_writable bpf_test_finish
//	func onFinish(ctx *bpf.RawTPWritableContext) {
//		if ctx.Buffer() == 0 {
//			ctx.SetBuffer(-33) // the test run's syscall returns −EDOM
//		}
//	}
//
// Directive `//gobpf:raw_tp_writable <tracepoint>` — only the kernel's DEFINE_EVENT_WRITABLE tracepoints (others get −EINVAL at attach). Buffer / SetBuffer read and write
// the i32 at offset 0 of the writable buffer that args[0] points to (no other offset, width or args read). vmlinux's bpf_test_finish buffer is
// the err of BPF_PROG_TEST_RUN, and the written value becomes the return value of the test run's syscall — **it fires on every test run in the system** (write only for your
// own tgid). No result. Attach with gobpf.AttachRawTPWritable. A non-root loader needs CAP_BPF + CAP_PERFMON.

// RawTPWritableContext is the context of a raw_tp_writable (BPF_PROG_TYPE_RAW_TRACEPOINT_WRITABLE) program (bpf_raw_tracepoint_args).
type RawTPWritableContext struct{ _ [0]func() }

// Buffer is eBPF side only: reads the i32 at offset 0 of the writable buffer (ebpf.tp.buffer.load).
func (c *RawTPWritableContext) Buffer() int32 { panic(ebpfOnly("RawTPWritableContext.Buffer")) }

// SetBuffer is eBPF side only: writes an i32 at offset 0 of the writable buffer (ebpf.tp.buffer.store).
func (c *RawTPWritableContext) SetBuffer(v int32) { panic(ebpfOnly("RawTPWritableContext.SetBuffer")) }
