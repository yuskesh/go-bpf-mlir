package bpf

import (
	"fmt"
	"reflect"

	"github.com/cilium/ebpf"

	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// map-in-map (bpf-mlir's array_of_maps and hash_of_maps):
//
//	var Tenants = bpf.ArrayOfMaps[uint32, uint64]{MaxEntries: 8, Inner: bpf.InnerSpec{Kind: bpf.InnerHash, MaxEntries: 64}}
//
//	if m := Tenants.Lookup(t); m != nil {     // if the outer slot holds an inner map
//		if p := m.Lookup(k); p != nil { … }   // the inner map has the same operations as Array / Hash
//		m.AtomicAdd(k, 1)
//	}
//
//	in, _ := Tenants.NewInner()   // user space: create an inner map of the template's shape
//	in.Put(1, 10)
//	Tenants.Set(3, in)            // insert it into outer slot 3
//
// The inner map's kind, key, value and max_entries are decided by the declaration's Inner and the type arguments (the kernel only accepts maps of the same shape as the template — otherwise −EINVAL).
// The eBPF side only does Lookup on the outer map (there is no outer Update / Delete — bpf-mlir rejects them), and the inner handle m exists only inside the checked branch; it cannot leave it for a loop, a subprogram,
// or outside the branch. The inner V is a 32 / 64-bit integer (no record or per-CPU inner maps — see limits). There are no two levels (a map in a map in a map).

// InnerKind is the kind of the inner map.
type InnerKind uint32

// Inner map kinds (constants only).
const (
	InnerArray   InnerKind = 1 // BPF_MAP_TYPE_ARRAY (the key is 0..MaxEntries-1 — every slot exists as 0)
	InnerHash    InnerKind = 2 // BPF_MAP_TYPE_HASH
	InnerLRUHash InnerKind = 3 // BPF_MAP_TYPE_LRU_HASH (creating the map needs CAP_BPF)
)

// InnerSpec is the declaration of the inner map's template (Kind and MaxEntries are constants).
type InnerSpec struct {
	// Kind is the kind of the inner map.
	Kind InnerKind
	// MaxEntries is the number of elements of the inner map (a nonzero constant).
	MaxEntries uint32
}

// ArrayOfMaps is the declaration of a BPF_MAP_TYPE_ARRAY_OF_MAPS (the outer key is a u32 index). K / V are the inner map's key and value.
type ArrayOfMaps[K Key32, V KprobeInt] struct {
	// MaxEntries is the number of outer slots (a nonzero constant).
	MaxEntries uint32
	// Inner is the inner map's template.
	Inner InnerSpec
}

// HashOfMaps is the declaration of a BPF_MAP_TYPE_HASH_OF_MAPS (the outer key is OK). K / V are the inner map's key and value.
type HashOfMaps[OK Key32, K Key32, V KprobeInt] struct {
	// MaxEntries is the maximum number of outer entries (a nonzero constant).
	MaxEntries uint32
	// Inner is the inner map's template.
	Inner InnerSpec
}

// InnerMap is an inner map — on the eBPF side, the handle inside the checked branch of an outer Lookup; in user space, a map created by NewInner.
type InnerMap[K Key32, V KprobeInt] struct {
	m *ebpf.Map
}

// Lookup is eBPF side only: the inner map in outer slot k (nil if none). Use it only in the shape `if m := M.Lookup(k); m != nil { … }`.
func (o *ArrayOfMaps[K, V]) Lookup(k uint32) *InnerMap[K, V] { panic(ebpfOnly("ArrayOfMaps.Lookup")) }

// Lookup is eBPF side only: the inner map at outer key k (nil if none). Use it only in the shape `if m := M.Lookup(k); m != nil { … }`.
func (o *HashOfMaps[OK, K, V]) Lookup(k OK) *InnerMap[K, V] { panic(ebpfOnly("HashOfMaps.Lookup")) }

// Lookup is eBPF side only: a pointer to the value of the inner key (nil if none — the same shape as Array.Lookup).
func (m *InnerMap[K, V]) Lookup(k K) *V { panic(ebpfOnly("InnerMap.Lookup")) }

// Update is eBPF side only: writes a value at the inner key (the same as Array.Update).
func (m *InnerMap[K, V]) Update(k K, v V) { panic(ebpfOnly("InnerMap.Update")) }

// AtomicAdd is eBPF side only: atomically adds d to the value of the inner key (only when present — the same as Array.AtomicAdd).
func (m *InnerMap[K, V]) AtomicAdd(k K, d V) { panic(ebpfOnly("InnerMap.AtomicAdd")) }

// NewInner is user space only: creates a new inner map of the template's shape (Inner and the type arguments) (after the outer Load — insert it into the outer map with Set).
func (o *ArrayOfMaps[K, V]) NewInner() (*InnerMap[K, V], error) {
	return newInner[K, V](o, "ArrayOfMaps.NewInner")
}

// NewInner is user space only (the same as ArrayOfMaps.NewInner).
func (o *HashOfMaps[OK, K, V]) NewInner() (*InnerMap[K, V], error) {
	return newInner[K, V](o, "HashOfMaps.NewInner")
}

// Set is user space only: inserts the inner map into outer slot k (the previous inner map leaves the outer map — the user's handle stays valid until Close).
func (o *ArrayOfMaps[K, V]) Set(k uint32, in *InnerMap[K, V]) error {
	return outerSet(o, "ArrayOfMaps.Set", k, in.m)
}

// Set is user space only (the same as ArrayOfMaps.Set).
func (o *HashOfMaps[OK, K, V]) Set(k OK, in *InnerMap[K, V]) error {
	return outerSet(o, "HashOfMaps.Set", k, in.m)
}

// Remove is user space only: empties outer slot k.
func (o *ArrayOfMaps[K, V]) Remove(k uint32) error { return mapRemove(o, "ArrayOfMaps.Remove", k) }

// Remove is user space only (the same as ArrayOfMaps.Remove).
func (o *HashOfMaps[OK, K, V]) Remove(k OK) error { return mapRemove(o, "HashOfMaps.Remove", k) }

// Get is user space only: the value of the inner key.
func (m *InnerMap[K, V]) Get(k K) (V, error) {
	var v V
	if err := m.m.Lookup(k, &v); err != nil {
		return v, fmt.Errorf("InnerMap.Get: key %v: %w", k, err)
	}
	return v, nil
}

// Put is user space only: writes a value at the inner key.
func (m *InnerMap[K, V]) Put(k K, v V) error {
	if err := m.m.Put(k, v); err != nil {
		return fmt.Errorf("InnerMap.Put: key %v: %w", k, err)
	}
	return nil
}

// Close is user space only: closes the user's handle (an inner map inserted into the outer map stays in the kernel while the outer map holds a reference).
func (m *InnerMap[K, V]) Close() error { return m.m.Close() }

func newInner[K Key32, V KprobeInt](outer any, method string) (*InnerMap[K, V], error) {
	if _, err := binding.Map(outer, method); err != nil {
		return nil, err
	}
	spec := binding.InnerSpec(outer)
	if spec == nil {
		return nil, fmt.Errorf("%s: map %s has no inner map template in the loaded collection", method, binding.Symbol(outer))
	}
	m, err := ebpf.NewMap(spec.Copy())
	if err != nil {
		return nil, fmt.Errorf("%s: map %s: create the inner map: %w", method, binding.Symbol(outer), err)
	}
	return &InnerMap[K, V]{m: m}, nil
}

func outerSet[K any](outer any, method string, k K, in *ebpf.Map) error {
	om, err := binding.Map(outer, method)
	if err != nil {
		return err
	}
	if err := om.Put(k, in); err != nil {
		return fmt.Errorf("%s: map %s key %v: %w", method, binding.Symbol(outer), k, err)
	}
	return nil
}

// GobpfTypes is an internal API of the gobpf runtime — the outer key and value (a u32 inner map fd).
func (o *ArrayOfMaps[K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfTypes is an internal API of the gobpf runtime (the same as ArrayOfMaps.GobpfTypes — the outer key is OK).
func (o *HashOfMaps[OK, K, V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[OK](), reflect.TypeFor[uint32]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (o *ArrayOfMaps[K, V]) GobpfMapKind() string { return "array_of_maps" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (o *HashOfMaps[OK, K, V]) GobpfMapKind() string { return "hash_of_maps" }

// GobpfInner is an internal API of the gobpf runtime: the inner template's kind, key and value types, and max_entries (Inner of bindrt's MapDecl).
func (o *ArrayOfMaps[K, V]) GobpfInner() (kind string, key, value reflect.Type, maxEntries uint32) {
	return innerKindName(o.Inner.Kind), reflect.TypeFor[K](), reflect.TypeFor[V](), o.Inner.MaxEntries
}

// GobpfInner is an internal API of the gobpf runtime (the same as ArrayOfMaps.GobpfInner).
func (o *HashOfMaps[OK, K, V]) GobpfInner() (kind string, key, value reflect.Type, maxEntries uint32) {
	return innerKindName(o.Inner.Kind), reflect.TypeFor[K](), reflect.TypeFor[V](), o.Inner.MaxEntries
}

func innerKindName(k InnerKind) string {
	return map[InnerKind]string{InnerArray: "array", InnerHash: "hash", InnerLRUHash: "lru_hash"}[k]
}
