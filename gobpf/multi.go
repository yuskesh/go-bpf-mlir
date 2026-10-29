package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// AttachKprobeMulti attaches a kprobe_multi / kretprobe_multi program (a function value) to the list of kernel functions in its directive with one link
// (cilium's link.KprobeMulti / KretprobeMulti). **The order and numbering of the list follow the mtarget order in the embedded ELF's requirements** — function i gets cookie i
// (bpf-mlir's requirements_format.md contract — bpf.ProbeTargetIndex returns i). The user writes neither the list nor the cookies. The link applies system-wide
// (calls from every process — read-only). Pass only programs loaded by Load (Load checks that every function in the list exists, the argument types (mtarget, kprobearg), and
// whether a kprobe.multi link can be created (CONFIG_FPROBE — attach_type)). A non-root loader needs CAP_BPF + CAP_PERFMON.
func AttachKprobeMulti(o *Objects, fn any) (link.Link, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if e == nil || (e.Kind != "kprobe_multi" && e.Kind != "kretprobe_multi") {
		return nil, wantKind(e, "kprobe_multi", "gobpf.AttachKprobeMulti")
	}
	parsed, err := parsedOf(o.obj)
	if err != nil {
		return nil, err
	}
	var syms []string
	for _, a := range parsed.Requirements().Attaches {
		if a.Program == e.Symbol {
			syms = a.MTargets
		}
	}
	if len(syms) == 0 {
		return nil, fmt.Errorf("gobpf.AttachKprobeMulti: program %s: the embedded ELF has no mtarget rows (regenerate with go generate)", e.Symbol)
	}
	cookies := make([]uint64, len(syms))
	for i := range cookies {
		cookies[i] = uint64(i)
	}
	opts := link.KprobeMultiOptions{Symbols: syms, Cookies: cookies}
	var l link.Link
	if e.Kind == "kretprobe_multi" {
		l, err = link.KretprobeMulti(p, opts)
	} else {
		l, err = link.KprobeMulti(p, opts)
	}
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachKprobeMulti: program %s at %v: %w", e.Symbol, syms, err)
	}
	return l, nil
}
