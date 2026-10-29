package gobpf

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
)

// AttachTracepoint attaches a tracepoint program (a function value) to the tracefs event in its directive `//gobpf:tracepoint <category>/<event>`
// (bpf-mlir's livecaps.AttachTracepointAllCPUs: it opens a perf event on every online CPU and attaches the program to the first event.
// cilium's link.Tracepoint opens only on CPU 0). After attaching it compares the tracepoint name in the link info with the declaration (closes with an error if they differ).
// Pass only programs loaded by Load — Load checks the event's existence (trace_tp) and the field offsets, widths and signs (tpfield — the event struct declaration) against
// the target's tracefs format. Root is required (the tracefs event id and a perf event with pid −1).
func AttachTracepoint(o *Objects, fn any) (*livecaps.TracepointLink, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "tracepoint", "gobpf.AttachTracepoint"); err != nil {
		return nil, err
	}
	group, name, ok := strings.Cut(e.Attach, "/")
	if !ok {
		return nil, fmt.Errorf("gobpf.AttachTracepoint: program %s: the attach point %q is not <category>/<event>", e.Symbol, e.Attach)
	}
	l, err := livecaps.AttachTracepointAllCPUs(group, name, p, nil)
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachTracepoint: program %s (tracepoint %s): %w", e.Symbol, e.Attach, err)
	}
	// There is no re-attach path (the event id is the tracefs id of the declared name) — confirm the link is a perf event link pointing at this program
	// (cilium's RawLink info does not carry the perf event's contents).
	info, err := l.BPF().Info()
	var pid ebpf.ProgramID
	pinfo, perr := p.Info()
	if perr == nil {
		pid, _ = pinfo.ID()
	}
	if err != nil || perr != nil || info.Type != link.PerfEventType || info.Program != pid {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachTracepoint: program %s: cannot confirm the attach point (link info: %v / %v)", e.Symbol, err, perr)
	}
	return l, nil
}

// AttachRawTP attaches a raw_tp program (a function value) to the raw tracepoint in its directive `//gobpf:raw_tp <tracepoint>` (cilium's
// link.AttachRawTracepoint). After attaching it compares the tracepoint name in the link info with the declaration. A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachRawTP(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "raw_tp", "gobpf.AttachRawTP"); err != nil {
		return nil, err
	}
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: e.Attach, Program: p})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachRawTP: program %s (raw tracepoint %s): %w", e.Symbol, e.Attach, err)
	}
	info, err := l.Info()
	if err != nil || info.RawTracepoint() == nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachRawTP: program %s: cannot confirm the attach point (link info: %v)", e.Symbol, err)
	}
	if got := info.RawTracepoint().Name; got != e.Attach {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachRawTP: program %s was attached to raw tracepoint %s, not %s; detached", e.Symbol, got, e.Attach)
	}
	return l, nil
}

// AttachRawTPWritable attaches a raw_tp_writable program (a function value) to the writable raw tracepoint in its directive `//gobpf:raw_tp_writable <tracepoint>`
// (cilium's link.AttachRawTracepoint accepts RawTracepointWritable). After attaching it compares the tracepoint name in the link info with
// the declaration and closes with an error if they differ (the same as AttachRawTP). If the tracepoint is not writable (writable_size is smaller than the program's buffer access) the kernel returns
// −EINVAL. **The program's writes affect every firing of the tracepoint** — filtering to its own tgid and so on is the program's job. A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachRawTPWritable(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "raw_tp_writable", "gobpf.AttachRawTPWritable"); err != nil {
		return nil, err
	}
	l, err := link.AttachRawTracepoint(link.RawTracepointOptions{Name: e.Attach, Program: p})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachRawTPWritable: program %s (raw tracepoint %s): %w", e.Symbol, e.Attach, err)
	}
	info, err := l.Info()
	if err != nil || info.RawTracepoint() == nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachRawTPWritable: program %s: cannot confirm the attach point (link info: %v)", e.Symbol, err)
	}
	if got := info.RawTracepoint().Name; got != e.Attach {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachRawTPWritable: program %s was attached to raw tracepoint %s, not %s; detached", e.Symbol, got, e.Attach)
	}
	return l, nil
}

// AttachKretprobe attaches a kretprobe program (a function value) to the return of the kernel function in its directive `//gobpf:kretprobe <fn>` (cilium's
// link.Kretprobe). Like AttachKprobe, cilium's silent re-attach to `__x64_<fn>` is stopped by Load's check (attach_alias) and by confirming
// the actual attach target after attaching. A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachKretprobe(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "kretprobe", "gobpf.AttachKretprobe"); err != nil {
		return nil, err
	}
	l, err := link.Kretprobe(e.Attach, p, nil)
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachKretprobe: program %s at %s: %w", e.Symbol, e.Attach, err)
	}
	got, err := kprobeTarget(l)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachKretprobe: program %s: cannot confirm the attach target %s (the loader may have attached an alias silently): %w", e.Symbol, e.Attach, err)
	}
	if got != e.Attach {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachKretprobe: program %s was attached to %s, not the declared %s (the loader substituted an alias); detached", e.Symbol, got, e.Attach)
	}
	return l, nil
}
