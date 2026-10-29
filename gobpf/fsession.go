package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// AttachFsession attaches an fsession program (a function value) to the entry and return of the kernel function in its directive (link.AttachTracing with
// AttachTraceFSession, which needs cilium/ebpf fsession support — upstream PR #2108). After attaching, it checks the link info's attach target (the vmlinux function name of the target BTF id)
// against the directive's function, and closes the link with an error if they differ. The kernel needs fsession (7.1.8 — on 6.12 / 6.6 the check in gobpf.Load stops it).
func AttachFsession(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "fsession", "gobpf.AttachFsession"); err != nil {
		return nil, err
	}
	at, err := fsessionAttachType() // an error in the build on plain upstream cilium/ebpf
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachFsession: program %s: %w", e.Symbol, err)
	}
	l, err := link.AttachTracing(link.TracingOptions{Program: p, AttachType: at})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachFsession: program %s at %s: %w", e.Symbol, e.Attach, err)
	}
	got, err := tracingLinkTarget(l)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachFsession: program %s: cannot confirm the attach target %s: %w", e.Symbol, e.Attach, err)
	}
	if got != e.Attach {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachFsession: program %s was attached to %s, not %s; detached", e.Symbol, got, e.Attach)
	}
	return l, nil
}

// tracingLinkTarget is the vmlinux function name of a tracing link's attach target (the link info's target_btf_id — read the same way as internal/tracetest.AttachTarget).
func tracingLinkTarget(l link.Link) (string, error) {
	info, err := l.Info()
	if err != nil {
		return "", fmt.Errorf("link info: %w", err)
	}
	tr := info.Tracing()
	if tr == nil {
		return "", fmt.Errorf("link %v is not a tracing link", info.Type)
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return "", err
	}
	typ, err := spec.TypeByID(btf.TypeID(tr.TargetBtfId))
	if err != nil {
		return "", fmt.Errorf("vmlinux BTF type %d: %w", tr.TargetBtfId, err)
	}
	f, ok := typ.(*btf.Func)
	if !ok {
		return "", fmt.Errorf("vmlinux BTF type %d is %T, not a function", tr.TargetBtfId, typ)
	}
	return f.Name, nil
}
