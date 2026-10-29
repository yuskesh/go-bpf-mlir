package bpf

import (
	"errors"
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"

	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// Maps without keys (bpf-mlir's queue, stack and bloom_filter):
//
//	var Pending = bpf.Queue[uint32]{MaxEntries: 64}
//
//	st := Pending.Push(id, bpf.PushAny)   // 0 or −E2BIG (full)
//	id, st := Pending.Pop()               // if empty, id is 0 and st is −ENOENT
//
// eBPF-side operations return a raw status (i64 — a statement that discards it is GB017) and cannot be placed inside a loop (a bpf-mlir limit — GB018). V is only an integer of 8 to 64 bits
// (bpf-mlir's schema rejects records). The user-space side has Put (push), Take (pop) and Get (peek) — names distinct from Push / Pop / Peek on the eBPF side
// (Go cannot have methods with the same name and two signatures — the same as Array's Lookup / Get). Creating the map needs CAP_BPF.

// PushFlag is the flags of Queue / Stack Push (BPF_ANY / BPF_EXIST — constants only).
type PushFlag uint64

// Push flags (PushAny does not insert when full and gives −E2BIG; PushExist drops the oldest element when full and inserts — the kernel's queue_stack_map_push_elem
// BPF_EXIST).
const (
	PushAny   PushFlag = 0
	PushExist PushFlag = 2
)

// Queue is the declaration of a BPF_MAP_TYPE_QUEUE (FIFO).
type Queue[V KprobeInt] struct {
	// MaxEntries is the number of elements (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// Stack is the declaration of a BPF_MAP_TYPE_STACK (LIFO).
type Stack[V KprobeInt] struct {
	// MaxEntries is the number of elements (a nonzero constant).
	MaxEntries uint32
}

// BloomFilter is the declaration of a BPF_MAP_TYPE_BLOOM_FILTER (a probabilistic set — false positives are possible, false negatives are not). The number of hash functions is the kernel default (5).
type BloomFilter[V KprobeInt] struct {
	// MaxEntries is the expected number of elements (a nonzero constant).
	MaxEntries uint32
	// ZeroSeed sets the hash seed to 0 (BPF_F_ZERO_SEED — a constant; false positives become the same on every run).
	ZeroSeed bool
}

// Push is eBPF side only: inserts v (flag is a constant — PushAny / PushExist). 0 or −E2BIG (full with PushAny).
func (m *Queue[V]) Push(v V, flag PushFlag) int64 { panic(ebpfOnly("Queue.Push")) }

// Pop is eBPF side only: takes out the oldest element. If empty, the value is 0 and status is −ENOENT.
func (m *Queue[V]) Pop() (V, int64) { panic(ebpfOnly("Queue.Pop")) }

// Peek is eBPF side only: reads the oldest element without taking it out. If empty, the value is 0 and status is −ENOENT.
func (m *Queue[V]) Peek() (V, int64) { panic(ebpfOnly("Queue.Peek")) }

// Push is eBPF side only (the same as Queue.Push).
func (m *Stack[V]) Push(v V, flag PushFlag) int64 { panic(ebpfOnly("Stack.Push")) }

// Pop is eBPF side only: takes out the newest element. If empty, the value is 0 and status is −ENOENT.
func (m *Stack[V]) Pop() (V, int64) { panic(ebpfOnly("Stack.Pop")) }

// Peek is eBPF side only: reads the newest element without taking it out.
func (m *Stack[V]) Peek() (V, int64) { panic(ebpfOnly("Stack.Peek")) }

// Push is eBPF side only: inserts v into the set (flags are any only). status is 0 (success).
func (m *BloomFilter[V]) Push(v V) int64 { panic(ebpfOnly("BloomFilter.Push")) }

// Peek is eBPF side only: 0 if v may be present, −ENOENT if not (0 can be a false positive).
func (m *BloomFilter[V]) Peek(v V) int64 { panic(ebpfOnly("BloomFilter.Peek")) }

// Put is user space only: inserts v (BPF_ANY — an error if full).
func (m *Queue[V]) Put(v V) error { return keylessPut(m, "Queue.Put", v) }

// Take is user space only: takes out the oldest element (if empty, an error wrapping ebpf.ErrKeyNotExist).
func (m *Queue[V]) Take() (V, error) { return keylessGet[V](m, "Queue.Take", true) }

// Get is user space only: reads the oldest element without taking it out.
func (m *Queue[V]) Get() (V, error) { return keylessGet[V](m, "Queue.Get", false) }

// Put is user space only (the same as Queue.Put).
func (m *Stack[V]) Put(v V) error { return keylessPut(m, "Stack.Put", v) }

// Take is user space only: takes out the newest element.
func (m *Stack[V]) Take() (V, error) { return keylessGet[V](m, "Stack.Take", true) }

// Get is user space only: reads the newest element without taking it out.
func (m *Stack[V]) Get() (V, error) { return keylessGet[V](m, "Stack.Get", false) }

// Put is user space only: inserts v into the set.
func (m *BloomFilter[V]) Put(v V) error { return keylessPut(m, "BloomFilter.Put", v) }

// Has is user space only: true if v may be present (false positives are possible), false if not.
func (m *BloomFilter[V]) Has(v V) (bool, error) {
	bm, err := binding.Map(m, "BloomFilter.Has")
	if err != nil {
		return false, err
	}
	if err := bm.Lookup(nil, &v); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("BloomFilter.Has: map %s value %v: %w", binding.Symbol(m), v, err)
	}
	return true, nil
}

func keylessPut[V any](key any, method string, v V) error {
	m, err := binding.Map(key, method)
	if err != nil {
		return err
	}
	if err := m.Update(nil, v, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("%s: map %s value %v: %w", method, binding.Symbol(key), v, err)
	}
	return nil
}

func keylessGet[V any](key any, method string, remove bool) (V, error) {
	var v V
	m, err := binding.Map(key, method)
	if err != nil {
		return v, err
	}
	if remove {
		err = m.LookupAndDelete(nil, &v)
	} else {
		err = m.Lookup(nil, &v)
	}
	if err != nil {
		return v, fmt.Errorf("%s: map %s: %w", method, binding.Symbol(key), err)
	}
	return v, nil
}

// GobpfTypes is an internal API of the gobpf runtime — the key of a map without keys is nil.
func (m *Queue[V]) GobpfTypes() (key, value reflect.Type) { return nil, reflect.TypeFor[V]() }

// GobpfTypes is an internal API of the gobpf runtime (the same as Queue.GobpfTypes).
func (m *Stack[V]) GobpfTypes() (key, value reflect.Type) { return nil, reflect.TypeFor[V]() }

// GobpfTypes is an internal API of the gobpf runtime (the same as Queue.GobpfTypes).
func (m *BloomFilter[V]) GobpfTypes() (key, value reflect.Type) { return nil, reflect.TypeFor[V]() }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *Queue[V]) GobpfMapKind() string { return "queue" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *Stack[V]) GobpfMapKind() string { return "stack" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *BloomFilter[V]) GobpfMapKind() string { return "bloom_filter" }

// GobpfMapFlags is an internal API of the gobpf runtime: the bloom flags (BPF_F_ZERO_SEED = 64 if ZeroSeed).
func (m *BloomFilter[V]) GobpfMapFlags() uint64 {
	if m.ZeroSeed {
		return 64
	}
	return 0
}
