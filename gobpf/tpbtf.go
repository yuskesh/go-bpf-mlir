package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// AttachTPBTF attaches a tp_btf program (a function value) to the tracepoint in its directive `//gobpf:tp_btf <tracepoint>` (cilium's
// link.AttachTracing). After attaching, it compares the link's actual attach target (the tracepoint name) with the declaration and closes the link with an error if they differ
// (the tracepoint name in the raw tracepoint link's info). Pass only programs loaded by Load — Load checks the tracepoint argument types (attach / arg), kernel struct fields (kfield),
// and the handling of arguments that may be NULL (arg_nullable — 6.6 stops). Programs from LoadUnchecked have not been checked for these.
// A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachTPBTF(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "tp_btf", "gobpf.AttachTPBTF"); err != nil {
		return nil, err
	}
	l, err := link.AttachTracing(link.TracingOptions{Program: p})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachTPBTF: program %s (tracepoint %s): %w", e.Symbol, e.Attach, err)
	}
	info, err := l.Info()
	if err != nil || info.RawTracepoint() == nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachTPBTF: program %s: cannot confirm the attach point (link info: %v)", e.Symbol, err)
	}
	if got := info.RawTracepoint().Name; got != e.Attach {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachTPBTF: program %s was attached to tracepoint %s, not %s; detached", e.Symbol, got, e.Attach)
	}
	return l, nil
}
