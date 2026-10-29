package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// AttachFmodRet attaches an fmod_ret program (a function value) to the entry trampoline of the kernel function in its directive `//gobpf:fmod_ret <fn> nargs=<N>`
// (cilium's link.AttachTracing with AttachModifyReturn). After attaching, it checks the link info's attach target (the vmlinux function name of the target BTF id)
// against the directive's function, and closes the link with an error if they differ (the fsession shape). **It does not restrict which function** (the kernel decides —
// functions allowed for error injection, `security_` functions and the kernel's fmodret set; others fail the load with "not modifiable") — a program that returns non-zero
// skips the original function, so choosing the function is the caller's responsibility. A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachFmodRet(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "fmod_ret", "gobpf.AttachFmodRet"); err != nil {
		return nil, err
	}
	l, err := link.AttachTracing(link.TracingOptions{Program: p, AttachType: ebpf.AttachModifyReturn})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachFmodRet: program %s at %s: %w", e.Symbol, e.Attach, err)
	}
	got, err := tracingLinkTarget(l)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachFmodRet: program %s: cannot confirm the attach target %s: %w", e.Symbol, e.Attach, err)
	}
	if got != e.Attach {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachFmodRet: program %s was attached to %s, not %s; detached", e.Symbol, got, e.Attach)
	}
	return l, nil
}
