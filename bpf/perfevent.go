package bpf

// perf_event programs (bpf-mlir's perf_event kind):
//
//	func onSample(ctx *bpf.PerfEventContext) {
//		Last.Update(0, ctx.SamplePeriod())
//	}
//
// A function whose first parameter has type *PerfEventContext and that has no result is a perf_event program (there is no directive; the verdict is done). It attaches to an event
// the user opened with perf_event_open (pass the fd to gobpf.AttachPerfEvent; the event type, pid / cpu and sample_period are loader inputs). The program runs on each
// sample (overflow) of the event. The only readable ctx field is sample_period (regs and addr of bpf_perf_event_data are not in bpf-mlir's capability table), and the arch is x86_64 only
// (the offset depends on the arch's pt_regs; the requirements' arch row is checked before load). A non-root loader needs CAP_BPF + CAP_PERFMON and permission
// to open the event (kernel.perf_event_paranoid; with 2, an exclude_kernel event on its own thread).

// PerfEventContext is the context of a perf_event program (struct bpf_perf_event_data).
type PerfEventContext struct{ _ [0]func() }

// SamplePeriod is eBPF side only: the period of this sample (sample_period of bpf_perf_event_data; the sample_period of the perf_event_open attr, or with freq
// sampling the value the kernel adjusted).
func (c *PerfEventContext) SamplePeriod() uint64 { panic(ebpfOnly("PerfEventContext.SamplePeriod")) }
