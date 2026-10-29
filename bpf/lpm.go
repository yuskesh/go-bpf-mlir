package bpf

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"

	"github.com/cilium/ebpf"

	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// LPMValue is the value type of LPMTrie4 (a 32 / 64-bit integer — the same rule as integer values of the hash family).
type LPMValue interface {
	~uint32 | ~uint64 | ~int32 | ~int64
}

// LPMTrie4 is a BPF_MAP_TYPE_LPM_TRIE table of IPv4 prefixes. The bpf side owns the key (8 bytes of {prefixlen: u32, addr: u8[4]} —
// bpf-mlir's convention; flags are BPF_F_NO_PREALLOC). Write it as a package-level variable:
//
//	var Deny = bpf.LPMTrie4[uint32]{MaxEntries: 1024}
//
// The eBPF side is **read only** — `v, ok := Deny.Lookup([4]byte{a, b, c, d})` (longest match of the address, returned by value — it returns no pointer, so
// writes to a borrow and AtomicAdd cannot be formed by type). User space builds the table with `netip.Prefix` (Put / Remove).
type LPMTrie4[V LPMValue] struct {
	// MaxEntries is the maximum number of prefixes (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// LPMKey4 is the key layout of LPMTrie4 (the schema record gobpf_lpm_key4). **An internal type of the gobpf runtime** — users use netip.Prefix.
// Addr is in network order (the address bytes as is), and PrefixLen is in host order.
type LPMKey4 struct {
	PrefixLen uint32   `schema:"prefixlen"`
	Addr      [4]uint8 `schema:"addr"`
}

// Lookup is eBPF side only: the value of the longest prefix containing addr (4 bytes in network order — the packet's byte order as is) and true,
// or 0 and false if none. Use it in the shape `if v, ok := M.Lookup(a); ok { … }` or `v, ok := M.Lookup(a)`, where a is a `[4]byte{…}` composite literal.
// The value is read only once (it does not become a value mixed with a concurrent Put from user space).
func (m *LPMTrie4[V]) Lookup(addr [4]byte) (V, bool) { panic(ebpfOnly("LPMTrie4.Lookup")) }

// lpmKey makes p a key. A prefix that is not IPv4, is invalid, or has host bits set (p != p.Masked()) is an error — it is not rounded silently
// (the kernel stores bits outside prefixlen too and returns them in iteration).
func lpmKey(method string, p netip.Prefix) (LPMKey4, error) {
	if !p.IsValid() {
		return LPMKey4{}, fmt.Errorf("%s: invalid prefix %v", method, p)
	}
	if !p.Addr().Is4() {
		return LPMKey4{}, fmt.Errorf("%s: prefix %v is not IPv4 (LPMTrie4 holds IPv4 prefixes only)", method, p)
	}
	if p != p.Masked() {
		return LPMKey4{}, fmt.Errorf("%s: prefix %v has host bits set — use %v (gobpf does not mask it silently)", method, p, p.Masked())
	}
	return LPMKey4{PrefixLen: uint32(p.Bits()), Addr: p.Addr().As4()}, nil
}

// Put is user space only: sets prefix p's value to v (replacing it if present). A new prefix in a full table is a kernel error (ENOSPC).
func (m *LPMTrie4[V]) Put(p netip.Prefix, v V) error {
	k, err := lpmKey("LPMTrie4.Put", p)
	if err != nil {
		return err
	}
	mp, err := binding.Map(m, "LPMTrie4.Put")
	if err != nil {
		return err
	}
	if err := mp.Put(k, v); err != nil {
		return fmt.Errorf("LPMTrie4.Put: map %s prefix %v: %w", binding.Symbol(m), p, err)
	}
	return nil
}

// Remove is user space only: deletes prefix p (a missing prefix is a kernel ENOENT error).
func (m *LPMTrie4[V]) Remove(p netip.Prefix) error {
	k, err := lpmKey("LPMTrie4.Remove", p)
	if err != nil {
		return err
	}
	mp, err := binding.Map(m, "LPMTrie4.Remove")
	if err != nil {
		return err
	}
	if err := mp.Delete(k); err != nil {
		return fmt.Errorf("LPMTrie4.Remove: map %s prefix %v: %w", binding.Symbol(m), p, err)
	}
	return nil
}

// Match is user space only: the value of the longest prefix containing a and true, or 0 and false if none (the kernel's longest match — the same as Lookup on the eBPF side).
func (m *LPMTrie4[V]) Match(a netip.Addr) (V, bool, error) {
	var v V
	if !a.Is4() {
		return v, false, fmt.Errorf("LPMTrie4.Match: address %v is not IPv4", a)
	}
	mp, err := binding.Map(m, "LPMTrie4.Match")
	if err != nil {
		return v, false, err
	}
	if err := mp.Lookup(LPMKey4{PrefixLen: 32, Addr: a.As4()}, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return v, false, nil
		}
		return v, false, fmt.Errorf("LPMTrie4.Match: map %s address %v: %w", binding.Symbol(m), a, err)
	}
	return v, true, nil
}

// Iterate is user space only: every prefix and value in the table (`for it.Next() { it.Prefix(), it.Value() }; it.Err()`).
func (m *LPMTrie4[V]) Iterate() *LPMIterator[V] {
	mp, err := binding.Map(m, "LPMTrie4.Iterate")
	if err != nil {
		return &LPMIterator[V]{err: err}
	}
	return &LPMIterator[V]{it: mp.Iterate()}
}

// LPMIterator is the user-space iterator of LPMTrie4.
type LPMIterator[V LPMValue] struct {
	it  *ebpf.MapIterator
	k   LPMKey4
	v   V
	err error
}

// Next reads the next entry (false at the end or on an error — tell them apart with Err).
func (it *LPMIterator[V]) Next() bool {
	if it.err != nil {
		return false
	}
	return it.it.Next(&it.k, &it.v)
}

// Prefix is the current entry's prefix.
func (it *LPMIterator[V]) Prefix() netip.Prefix {
	return netip.PrefixFrom(netip.AddrFrom4(it.k.Addr), int(it.k.PrefixLen))
}

// Value is the current entry's value.
func (it *LPMIterator[V]) Value() V { return it.v }

// Err is the iteration error (before load, after Close, or a kernel error).
func (it *LPMIterator[V]) Err() error {
	if it.err != nil {
		return it.err
	}
	return it.it.Err()
}

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key is LPMKey4.
func (m *LPMTrie4[V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[LPMKey4](), reflect.TypeFor[V]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *LPMTrie4[V]) GobpfMapKind() string { return "lpm_trie" }

// GobpfMapFlags is an internal API of the gobpf runtime: the map flags (lpm_trie is BPF_F_NO_PREALLOC = 1 — the kernel requires it). gobpf's Load passes them to bindrt as the map declaration's
// flags (in bpf-mlir, omitted flags mean "flags 0", and a difference from the ELF's flags is flags_undeclared). A map type without this method
// has flags 0.
func (m *LPMTrie4[V]) GobpfMapFlags() uint64 { return 1 }
