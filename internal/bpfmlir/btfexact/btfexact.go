// Package btfexact looks up types in a target BTF by their complete name.
// cilium v0.22.0's Spec.TypeByName / AnyTypesByName group candidates
// by essential name (the part before the last "___") and then drop the others
// with slices.Delete while still advancing the index, so the element after a
// deleted one is never examined (docs/upstream_suspects.md U4). On the four
// target kernels this returns "multiple matching types" for 7.x scx kfuncs
// with ___v2 / ___v2_impl siblings and for FUNCs starting with "____", and
// "not found" for FUNCs starting with "___". This package builds its own
// complete-name index from Spec.All instead, so no lookup depends on the
// essential-name index.
package btfexact

import (
	"errors"
	"fmt"
	"iter"
	"sync"

	"github.com/cilium/ebpf/btf"
)

// ErrMultiple reports more than one type of the requested kind with the name.
// The error texts are cilium v0.22.0's (bare btf.ErrNotFound and
// "type <name>(<Go type>): multiple matching types"), so messages that wrap
// them do not change where the answer does not.
var ErrMultiple = errors.New("multiple matching types")

type index map[string][]btf.Type

var cache sync.Map // *btf.Spec -> index; only complete scans are stored.

// all is the type sequence the index reads; tests replace it to inject scan errors.
var all = func(spec *btf.Spec) iter.Seq2[btf.Type, error] { return spec.All() }

func indexOf(spec *btf.Spec) (index, error) {
	if v, ok := cache.Load(spec); ok {
		return v.(index), nil
	}
	idx := index{}
	for typ, err := range all(spec) {
		if err != nil {
			// A partial index would turn an unread type into "not found" or
			// hide a second candidate; return the error and cache nothing.
			return nil, fmt.Errorf("reading the target BTF: %w", err)
		}
		if n := typ.TypeName(); n != "" {
			idx[n] = append(idx[n], typ)
		}
	}
	v, _ := cache.LoadOrStore(spec, idx)
	return v.(index), nil
}

// Types returns every type whose complete name is name, in type-ID order.
func Types(spec *btf.Spec, name string) ([]btf.Type, error) {
	idx, err := indexOf(spec)
	if err != nil {
		return nil, err
	}
	return idx[name], nil
}

// TypeByName stores into *out the single type of out's Go type (for example
// *btf.Func) whose complete name is name. None of that kind is btf.ErrNotFound
// (types of other kinds with the name do not count), two or more is
// ErrMultiple, and a BTF read error is returned as is.
func TypeByName[T btf.Type](spec *btf.Spec, name string, out *T) error {
	ts, err := Types(spec, name)
	if err != nil {
		return err
	}
	var found []T
	for _, t := range ts {
		if v, ok := t.(T); ok {
			found = append(found, v)
		}
	}
	switch len(found) {
	case 0:
		return btf.ErrNotFound
	case 1:
		*out = found[0]
		return nil
	}
	return fmt.Errorf("type %s(%T): %w", name, *out, ErrMultiple)
}
