package bpf

import "reflect"

// Local storage maps (bpf-mlir's storage.get / storage.delete). The value is attached to a kernel object (the owner — task, socket, cgroup,
// inode), and the kernel deletes it when the object ends. There is no key and no MaxEntries (the declaration is `var Seen = bpf.TaskStorage[V]{}`). V is the same as an Array value
// (a 32 / 64-bit integer or a record).
//
// eBPF side: the owner is a pointer of a kernel local type (a checked p from tp_btf's bpf.TPArg[T] or fentry's bpf.FentryArg[T], or following `if m := p.F; m != nil`),
// and T's `kernel:"<struct>"` must be the struct of the map kind (task_struct, sock, cgroup, inode):
//
//	if v := Seen.Get(child, bpf.Create); v != nil { bpf.AtomicAdd(&v.N, 1) }   // created as 0 if missing (the same borrow rules as Lookup's checked branch)
//	st := Seen.Delete(child)                                                    // raw status (0 or a negative errno — −ENOENT if missing)
//
// The kernel decides which program types can use it (7.1.8: task / cgrp all; sk tracing fentry / fexit and net types — not tp_btf; inode
// lsm only) — gobpf.Load's check and the verifier stop the rest. User-space side: GetFD(fd) / DeleteFD(fd) — the key is the owner's fd (a pidfd for a task, the
// socket fd for a socket, the cgroup directory fd for a cgroup, a file fd for an inode).

// StorageFlag is how Get creates (bpf.Create creates as 0 if missing, bpf.NoCreate gives nil if missing).
type StorageFlag uint32

// Constants for how Get creates (write them as constants — the frontend stops expressions).
const (
	NoCreate StorageFlag = 0
	Create   StorageFlag = 1
)

// TaskStorage is the declaration of a BPF_MAP_TYPE_TASK_STORAGE map (the owner is task_struct — since kernel 5.11).
type TaskStorage[V any] struct{ _ [0]V }

// SKStorage is the declaration of a BPF_MAP_TYPE_SK_STORAGE map (the owner is sock).
type SKStorage[V any] struct{ _ [0]V }

// CgrpStorage is the declaration of a BPF_MAP_TYPE_CGRP_STORAGE map (the owner is cgroup — since kernel 6.2).
type CgrpStorage[V any] struct{ _ [0]V }

// InodeStorage is the declaration of a BPF_MAP_TYPE_INODE_STORAGE map (the owner is inode — the kernel allows it only for lsm programs).
type InodeStorage[V any] struct{ _ [0]V }

// Get is eBPF side only: a pointer to the owner's value (if missing and create is Create, it is created as 0; nil if it cannot be created). Use it only in the shape
// `if v := S.Get(p, bpf.Create); v != nil { … }`.
func (m *TaskStorage[V]) Get(owner any, create StorageFlag) *V { panic(ebpfOnly("TaskStorage.Get")) }

// Delete is eBPF side only: deletes the owner's value (raw status — the frontend stops a statement that discards it).
func (m *TaskStorage[V]) Delete(owner any) int64 { panic(ebpfOnly("TaskStorage.Delete")) }

// GetFD is the user-space side: the value of the pidfd's task.
func (m *TaskStorage[V]) GetFD(fd int) (V, error) {
	return mapGet[int32, V](m, "TaskStorage.GetFD", int32(fd))
}

// DeleteFD is the user-space side: deletes the value of the pidfd's task.
func (m *TaskStorage[V]) DeleteFD(fd int) error {
	return mapRemove(m, "TaskStorage.DeleteFD", int32(fd))
}

// Get is eBPF side only (the same as TaskStorage.Get — the owner is sock).
func (m *SKStorage[V]) Get(owner any, create StorageFlag) *V { panic(ebpfOnly("SKStorage.Get")) }

// Delete is eBPF side only (the same as TaskStorage.Delete).
func (m *SKStorage[V]) Delete(owner any) int64 { panic(ebpfOnly("SKStorage.Delete")) }

// GetFD is the user-space side: the value of the socket fd.
func (m *SKStorage[V]) GetFD(fd int) (V, error) {
	return mapGet[int32, V](m, "SKStorage.GetFD", int32(fd))
}

// DeleteFD is the user-space side: deletes the value of the socket fd.
func (m *SKStorage[V]) DeleteFD(fd int) error { return mapRemove(m, "SKStorage.DeleteFD", int32(fd)) }

// Get is eBPF side only (the same as TaskStorage.Get — the owner is cgroup).
func (m *CgrpStorage[V]) Get(owner any, create StorageFlag) *V { panic(ebpfOnly("CgrpStorage.Get")) }

// Delete is eBPF side only (the same as TaskStorage.Delete).
func (m *CgrpStorage[V]) Delete(owner any) int64 { panic(ebpfOnly("CgrpStorage.Delete")) }

// GetFD is the user-space side: the value of the cgroup directory fd.
func (m *CgrpStorage[V]) GetFD(fd int) (V, error) {
	return mapGet[int32, V](m, "CgrpStorage.GetFD", int32(fd))
}

// DeleteFD is the user-space side: deletes the value of the cgroup directory fd.
func (m *CgrpStorage[V]) DeleteFD(fd int) error {
	return mapRemove(m, "CgrpStorage.DeleteFD", int32(fd))
}

// Get is eBPF side only (the same as TaskStorage.Get — the owner is inode).
func (m *InodeStorage[V]) Get(owner any, create StorageFlag) *V { panic(ebpfOnly("InodeStorage.Get")) }

// Delete is eBPF side only (the same as TaskStorage.Delete).
func (m *InodeStorage[V]) Delete(owner any) int64 { panic(ebpfOnly("InodeStorage.Delete")) }

// GetFD is the user-space side: the value of the inode of a file fd.
func (m *InodeStorage[V]) GetFD(fd int) (V, error) {
	return mapGet[int32, V](m, "InodeStorage.GetFD", int32(fd))
}

// DeleteFD is the user-space side: deletes the value of the inode of a file fd.
func (m *InodeStorage[V]) DeleteFD(fd int) error {
	return mapRemove(m, "InodeStorage.DeleteFD", int32(fd))
}

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key is int32 (the owner's fd).
func (m *TaskStorage[V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[int32](), reflect.TypeFor[V]()
}

// GobpfTypes is an internal API of the gobpf runtime (the same as TaskStorage.GobpfTypes).
func (m *SKStorage[V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[int32](), reflect.TypeFor[V]()
}

// GobpfTypes is an internal API of the gobpf runtime (the same as TaskStorage.GobpfTypes).
func (m *CgrpStorage[V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[int32](), reflect.TypeFor[V]()
}

// GobpfTypes is an internal API of the gobpf runtime (the same as TaskStorage.GobpfTypes).
func (m *InodeStorage[V]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[int32](), reflect.TypeFor[V]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *TaskStorage[V]) GobpfMapKind() string { return "task_storage" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *SKStorage[V]) GobpfMapKind() string { return "sk_storage" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *CgrpStorage[V]) GobpfMapKind() string { return "cgrp_storage" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *InodeStorage[V]) GobpfMapKind() string { return "inode_storage" }

// GobpfMaxEntries is an internal API of the gobpf runtime: max_entries of a local storage map is 0 (it has no MaxEntries field).
func (m *TaskStorage[V]) GobpfMaxEntries() uint32 { return 0 }

// GobpfMaxEntries is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMaxEntries).
func (m *SKStorage[V]) GobpfMaxEntries() uint32 { return 0 }

// GobpfMaxEntries is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMaxEntries).
func (m *CgrpStorage[V]) GobpfMaxEntries() uint32 { return 0 }

// GobpfMaxEntries is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMaxEntries).
func (m *InodeStorage[V]) GobpfMaxEntries() uint32 { return 0 }

// GobpfMapFlags is an internal API of the gobpf runtime: the flags of a local storage map are BPF_F_NO_PREALLOC (1 — the kernel requires it).
func (m *TaskStorage[V]) GobpfMapFlags() uint64 { return 1 }

// GobpfMapFlags is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMapFlags).
func (m *SKStorage[V]) GobpfMapFlags() uint64 { return 1 }

// GobpfMapFlags is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMapFlags).
func (m *CgrpStorage[V]) GobpfMapFlags() uint64 { return 1 }

// GobpfMapFlags is an internal API of the gobpf runtime (the same as TaskStorage.GobpfMapFlags).
func (m *InodeStorage[V]) GobpfMapFlags() uint64 { return 1 }
