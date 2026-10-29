package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachPerfEvent attaches a perf_event program (a function value) to the fd of an event the user opened with perf_event_open (BPF_LINK_CREATE,
// cilium's link.AttachRawLink with ebpf.AttachPerfEvent). The program runs on each sample of the event. The event (type, pid / cpu, sample_period) and the fd's
// lifetime belong to the user — the link comes off at Close or at process exit unless pinned (the user still closes the fd after the link). Pass only programs loaded
// by Load — Load checks the arch (the assumed offsets of bpf_perf_event_data). A non-root loader needs CAP_BPF + CAP_PERFMON and permission to open the event.
func AttachPerfEvent(o *Objects, fn any, fd int) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "perf_event", "gobpf.AttachPerfEvent"); err != nil {
		return nil, err
	}
	l, err := link.AttachRawLink(link.RawLinkOptions{Target: fd, Program: p, Attach: ebpf.AttachPerfEvent})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachPerfEvent: program %s (perf event fd %d): %w", e.Symbol, fd, err)
	}
	return l, nil
}
