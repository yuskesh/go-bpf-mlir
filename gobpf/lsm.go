package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// AttachLSM attaches an lsm / lsm.s program (a function value) to the LSM hook in its directive `//gobpf:lsm <hook>` / `//gobpf:lsm_s <hook>`
// (cilium's link.AttachLSM, BPF_LSM_MAC). After attaching, it compares the link's actual attach target (the target BTF function bpf_lsm_<hook>) with the declaration,
// and closes the link with an error if they differ. **The link applies system-wide** — it hooks every process (filtering inside the program is the writer's responsibility).
// The link goes away at Close or at process exit unless pinned. Pass only programs loaded by Load — Load checks the hook's argument types (farg) and
// whether the kernel has BPF LSM (trace_lsm). A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachLSM(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil || (e.Kind != "lsm" && e.Kind != "lsm_s") {
		return nil, wantKind(e, "lsm", "gobpf.AttachLSM")
	}
	l, err := link.AttachLSM(link.LSMOptions{Program: p})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachLSM: program %s (hook %s): %w", e.Symbol, e.Attach, err)
	}
	got, err := lsmTarget(l)
	if err != nil {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachLSM: program %s: cannot confirm the attach point: %w", e.Symbol, err)
	}
	if want := "bpf_lsm_" + e.Attach; got != want {
		l.Close()
		return nil, fmt.Errorf("gobpf.AttachLSM: program %s was attached to %s, not %s; detached", e.Symbol, got, want)
	}
	return l, nil
}

// lsmTarget is the function name of an LSM link's attach target (the link info's target_btf_id looked up in the vmlinux BTF).
func lsmTarget(l link.Link) (string, error) {
	info, err := l.Info()
	if err != nil {
		return "", err
	}
	tr := info.Tracing()
	if tr == nil {
		return "", fmt.Errorf("link type %v is not a tracing link", info.Type)
	}
	spec, err := btf.LoadKernelSpec()
	if err != nil {
		return "", err
	}
	typ, err := spec.TypeByID(btf.TypeID(tr.TargetBtfId))
	if err != nil {
		return "", err
	}
	f, ok := typ.(*btf.Func)
	if !ok {
		return "", fmt.Errorf("vmlinux BTF type %d is %T, not a function", tr.TargetBtfId, typ)
	}
	return f.Name, nil
}
