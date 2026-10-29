package bpf

import (
	"encoding/binary"
	"fmt"
	"reflect"

	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// StackTrace is the declaration of a BPF_MAP_TYPE_STACK_TRACE: the key is a stack id (u32), and the value is the kernel stack's IPs (u64 × Depth).
// Write it as a package-level variable:
//
//	var Stacks = bpf.StackTrace{MaxEntries: 256, Depth: 32}
//
//	//gobpf:fentry do_sys_poll
//	func onPoll(ctx *bpf.FentryContext) {
//		st := Stacks.KernelID(ctx, 0) // an id (≥ 0) or a negative errno
//		…
//	}
//
// **Depth × 8 must be at most the kernel's perf_event_max_stack (sysctl kernel.perf_event_max_stack — default 127)** — it is an environment value, so compile does not look at it;
// gobpf.Load reads the host's sysctl and stops with a named error before creating the map. There is no operation to read or write entries from the eBPF side (bpf-mlir rejects other ops on
// a stack_trace map inside a program).
//
// **id bucket collisions**: the kernel puts the stack hash into a bucket (MaxEntries rounded up to a power of 2) — on hitting a bucket that already holds another stack,
// KernelID gives −EEXIST, and KernelIDReuse takes one free element (of MaxEntries) to overwrite and returns the same id (the previous stack is lost) — **if there is no free element,
// −ENOMEM** (it takes a new element before returning the old one, so it cannot overwrite when every element is in a bucket — observed with MaxEntries 1).
// The same path gets the same id only with a MaxEntries large enough to have no collisions.
type StackTrace struct {
	// MaxEntries is the number of stacks it can hold (elements — a nonzero constant. The number of buckets is this rounded up to a power of 2).
	MaxEntries uint32
	// Depth is the maximum number of IPs in one stack (a nonzero constant).
	Depth uint32
}

// KernelID is eBPF side only (only in fentry program bodies): records the current kernel stack, excluding the first skip frames, and returns **the raw status**
// (helper bpf_get_stackid). Success is an id (≥ 0 — the key for Get on the user side); failure is a negative errno: depth ≤ skip gives −EFAULT (−14), a bucket collision gives −EEXIST (−17).
// **With skip 0, the first frame is this call's return address inside the eBPF program** (a different address per call site), followed by the fentry trampoline,
// the attached function, and its caller, in that order. // skip is a constant 0 to 255. **A statement that discards the status is stopped by the frontend with GB017** — if you do not count it, write `_ = Stacks.KernelID(ctx, 0)` explicitly. It cannot be written in a loop body.
func (m *StackTrace) KernelID(ctx *FentryContext, skip uint32) int64 {
	panic(ebpfOnly("StackTrace.KernelID"))
}

// KernelIDReuse is the same as KernelID, but overwrites the previous stack on a bucket collision (BPF_F_REUSE_STACKID — never −EEXIST, but −ENOMEM (−12) if there is no free element).
func (m *StackTrace) KernelIDReuse(ctx *FentryContext, skip uint32) int64 {
	panic(ebpfOnly("StackTrace.KernelIDReuse"))
}

// Get is user space only: the IPs of stack id (trailing zeros removed — the first is the innermost frame). A missing id is an error. Turning IPs into names is up to the user
// (/proc/kallsyms — some kernels show 0 to non-root processes).
func (m *StackTrace) Get(id uint32) ([]uint64, error) {
	mp, err := binding.Map(m, "StackTrace.Get")
	if err != nil {
		return nil, err
	}
	buf := make([]byte, mp.ValueSize())
	if err := mp.Lookup(id, buf); err != nil {
		return nil, fmt.Errorf("StackTrace.Get: map %s id %d: %w", binding.Symbol(m), id, err)
	}
	ips := make([]uint64, 0, len(buf)/8)
	for i := 0; i+8 <= len(buf); i += 8 {
		ips = append(ips, binary.LittleEndian.Uint64(buf[i:]))
	}
	for len(ips) > 0 && ips[len(ips)-1] == 0 {
		ips = ips[:len(ips)-1]
	}
	return ips, nil
}

// Delete is user space only: deletes stack id (frees the bucket). A non-reuse KernelID / UserID returns −EEXIST (−17) when the bucket is taken by another stack
// — **deleting stacks you have read** (Delete after Get) avoids bucket collisions and a full map. If you delete while an event with the same id
// is still unread, that event's Get gives ENOENT (the same stack has the same id) — delete only when the reader reads each id once.
func (m *StackTrace) Delete(id uint32) error { return mapRemove(m, "StackTrace.Delete", id) }

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key is a u32 and the value is [Depth]uint64.
func (m *StackTrace) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.ArrayOf(int(m.Depth), reflect.TypeFor[uint64]())
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *StackTrace) GobpfMapKind() string { return "stack_trace" }

// PerfEventArray is the declaration of a BPF_MAP_TYPE_PERF_EVENT_ARRAY: it outputs record V to per-CPU perf rings. V is a record
// (the same rules as bpf.RingBuf events). Write it as a package-level variable — MaxEntries cannot be written (0 — the loader sets it to the number of possible CPUs):
//
//	var Events = bpf.PerfEventArray[Event]{}
//
// The user side creates the rings of every CPU with gobpf.NewPerfReader(&Events, pages) and opens them **before attach** (gobpf.AttachFentry stops a program that outputs to a
// PerfEventArray without a reader — output to an empty CPU slot is dropped with −ENOENT).
//
// **Why use perf events when RingBuf exists**: (i) BPF_MAP_TYPE_RINGBUF exists since kernel 5.8 — compatibility with older kernels and with existing tools that read perf
// rings, (ii) per-CPU rings (no contention for reservations with other CPUs — **ordering is per CPU only**). If you need global ordering or are writing new code, RingBuf is the default
// (the kernels this project targets, 7.1.8 / 6.12 / 6.6, all have RingBuf).
type PerfEventArray[V any] struct{ _ [0]V }

// Output is eBPF side only (only in fentry program bodies): outputs v to the current CPU's perf ring (helper bpf_perf_event_output, BPF_F_CURRENT_CPU),
// and returns **the raw status**: 0 is success, −ENOENT (−2) means the current CPU's slot has no reader, −ENOSPC (−28) is a ring overflow (counted in the reader's Lost —
// the count matches only after the reader drains the overflowed ring and reads the next successful output from the same CPU). v is a record literal.
// **A statement that discards the status is stopped by the frontend with GB017** — if you do not count it, write `_ = Events.Output(ctx, …)` explicitly. It cannot be written in a loop body.
func (m *PerfEventArray[V]) Output(ctx *FentryContext, v V) int64 {
	panic(ebpfOnly("PerfEventArray.Output"))
}

// GobpfTypes is an internal API of the gobpf runtime — the key and value are u32 (CPU index → perf event fd). The event type V is GobpfEvent.
func (m *PerfEventArray[V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfEvent is an internal API of the gobpf runtime — the Go type of the payload record.
func (m *PerfEventArray[V]) GobpfEvent() reflect.Type { return reflect.TypeFor[V]() }

// GobpfMaxEntries is an internal API of the gobpf runtime — the declared MaxEntries (always 0 — the loader sets it to the number of possible CPUs).
func (m *PerfEventArray[V]) GobpfMaxEntries() uint32 { return 0 }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *PerfEventArray[V]) GobpfMapKind() string { return "perf_event_array" }
