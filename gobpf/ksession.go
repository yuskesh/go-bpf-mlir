package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// AttachKprobeSession attaches a kprobe_session program (a function value) to the entry and return of the kernel function in its directive `//gobpf:kprobe_session <fn>`
// (cilium's link.KprobeMulti with Session: true — a kprobe.multi link). **The info of a kprobe.multi link does not hold the function name** —
// after attaching, only the number of functions (Count = 1) can be confirmed. The kernel needs BPF_TRACE_KPROBE_SESSION and the kfunc signature `bpf_session_is_return(void *ctx)`
// (7.1.8 — on 6.12 / 6.6 the check in gobpf.Load stops before the load). A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachKprobeSession(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "kprobe_session", "gobpf.AttachKprobeSession"); err != nil {
		return nil, err
	}
	l, err := link.KprobeMulti(p, link.KprobeMultiOptions{Symbols: []string{e.Attach}, Session: true})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachKprobeSession: program %s at %s: %w", e.Symbol, e.Attach, err)
	}
	info, err := l.Info()
	if err != nil || info.KprobeMulti() == nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachKprobeSession: program %s: cannot confirm the attach (link info: %v)", e.Symbol, err)
	}
	if n := info.KprobeMulti().Count; n != 1 {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachKprobeSession: program %s: the link has %d functions, not 1 (%s); detached", e.Symbol, n, e.Attach)
	}
	return l, nil
}
