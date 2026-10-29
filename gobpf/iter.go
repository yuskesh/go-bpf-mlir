package gobpf

import (
	"fmt"

	"github.com/cilium/ebpf/link"
)

// AttachIter makes an iterator link of an iter program (a function value) over the map named by its directive (cilium's link.AttachIter).
// The iterator's output is read from the io.ReadCloser of the returned link's Open() (each read walks the map's elements from the start). The program runs per element and once for the final stop.
// A non-root loader needs CAP_BPF + CAP_PERFMON (for the load — the link and the read need no further capability).
func AttachIter(o *Objects, fn any) (*link.Iter, error) {
	p, err := o.Program(fn)
	if err != nil {
		return nil, err
	}
	e := o.entryOf(fn)
	if err := wantKind(e, "iter", "gobpf.AttachIter"); err != nil {
		return nil, err
	}
	m := o.coll.Maps[e.IterMap]
	if m == nil {
		return nil, fmt.Errorf("gobpf.AttachIter: program %s: the object has no map %s (its //gobpf:iter directive — regenerate with go generate)", e.Symbol, e.IterMap)
	}
	it, err := link.AttachIter(link.IterOptions{Program: p, Map: m})
	if err != nil {
		return nil, fmt.Errorf("gobpf.AttachIter: program %s over map %s: %w", e.Symbol, e.IterMap, err)
	}
	return it, nil
}
