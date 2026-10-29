package gobpf

import (
	"fmt"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/livecaps"
)

// AttachUSDT attaches a usdt program (a function value) to every USDT point `<provider>:<name>` (its directive) in the binary given to Load's WithUprobeTarget
// (bpf-mlir's glue livecaps.AttachUSDT: it reads the notes, writes the spec of point i (note order) at key i of the compiler's spec map `__ebpf_usdt_spec_<program>`,
// and attaches with cilium's Executable.Uprobe using Address (the point's file offset), Cookie i and RefCtrOffset (for points with a semaphore — the kernel raises the
// semaphore only while attached)). The binary is the fd Load checked (`/proc/self/fd/N` — the check and the attach see the same inode); t.PID is the process to attach to (0 means all).
// The result's Points hold each point's file offset, semaphore file offset and spec; Close closes the uprobes of all points. Pass only programs loaded by Load
// (Load checks the points, semaphores, argument sizes / signs and the number of points against the gobpf loader declaration — usdt_attach ref_ctr). The glue's uprobe is a perf uprobe —
// a non-root loader also needs CAP_SYS_ADMIN (the same as a single uprobe).
func AttachUSDT(o *Objects, fn any, t UprobeTarget) (*livecaps.USDTLink, error) {
	const api = "gobpf.AttachUSDT"
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "usdt", api); err != nil {
		return nil, err
	}
	ut := o.uprobes[e.Symbol]
	if ut == nil {
		return nil, fmt.Errorf("%s: program %s has no target — load with gobpf.Load(caps, gobpf.WithUprobeTarget(%s, <path>))", api, e.Symbol, e.Symbol)
	}
	spec := o.coll.Maps[requirements.USDTSpecMapPrefix+e.Symbol]
	if spec == nil {
		return nil, fmt.Errorf("%s: program %s has no USDT spec map %s%s (a usdt program without bpf.USDTArg — attaching it would read no spec; read an argument or drop the program)", api, e.Symbol, requirements.USDTSpecMapPrefix, e.Symbol)
	}
	provider, name, _ := strings.Cut(e.Attach, ":")
	l, err := livecaps.AttachUSDT(p, spec, fmt.Sprintf("/proc/self/fd/%d", ut.f.Fd()), provider, name, &livecaps.USDTOptions{PID: t.PID})
	if err != nil {
		return nil, fmt.Errorf("%s: program %s at %s in %s: %w", api, e.Symbol, e.Attach, ut.path, err)
	}
	return l, nil
}
