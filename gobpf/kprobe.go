package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// isTracingKind reports whether kind is a program kind that attaches to a kernel function rather than an interface (fentry, fexit, kprobe).
func isTracingKind(kind string) bool {
	return tracingAttachName(kind) != ""
}

// AttachKprobe attaches a kprobe program (a function value) to the entry of the kernel function in its directive `//gobpf:kprobe <fn>` (cilium's
// link.Kprobe). **When attaching to <fn> fails, cilium silently re-attaches to `__x64_<fn>` (the syscall wrapper — the argument registers differ)** —
// gobpf.Load checks before loading that <fn> exists and has no alias (the requirements' attach_alias), and after attaching this also compares the actual attach target
// (the function name in the perf kprobe link's info) with the declaration, closing the link with an error if they differ (a re-attach is never silent).
// Pass only programs loaded by Load (LoadUnchecked has not checked attach_alias or the argument types). A non-root loader needs
// CAP_BPF + CAP_PERFMON (and kernel.perf_event_paranoid). An xdp / sched_cls / fentry / fexit program is a named error.
func AttachKprobe(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "kprobe", "gobpf.AttachKprobe"); err != nil {
		return nil, err
	}
	l, err := link.Kprobe(e.Attach, p, nil)
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachKprobe: program %s at %s: %w", e.Symbol, e.Attach, err)
	}
	got, err := kprobeTarget(l)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachKprobe: program %s: cannot confirm the attach target %s (the loader may have attached an alias silently): %w", e.Symbol, e.Attach, err)
	}
	if got != e.Attach {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachKprobe: program %s was attached to %s, not the declared %s (the loader substituted an alias — the program would read the wrong registers); detached", e.Symbol, got, e.Attach)
	}
	return l, nil
}

// kprobeTarget is the function name of a kprobe link's actual attach target (the kprobe in bpf_link_info's perf_event — from kernel 6.6).
func kprobeTarget(l link.Link) (string, error) {
	info, err := l.Info()
	if err != nil {
		return "", err
	}
	pe := info.PerfEvent()
	if pe == nil || pe.Kprobe() == nil {
		return "", fmt.Errorf("link %v is not a perf-event kprobe link", info.Type)
	}
	return pe.Kprobe().Function, nil
}
