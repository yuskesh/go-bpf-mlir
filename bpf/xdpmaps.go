package bpf

import "reflect"

// XDP forwarding maps (bpf-mlir's XDP redirect maps): cpumap, devmap_hash, xskmap. The eBPF side has the same terminator as DevMap,
// `return M.Redirect(ctx, k, fallback)` / `return M.RedirectIf(ctx, cond, k, fallback, otherwise)` (only as the last statement of an xdp program body — the return value is
// the requested action, not whether delivery succeeded), and user space Sets the entries. The key and value are u32.

// CPUMap is the declaration of a BPF_MAP_TYPE_CPUMAP: the key is a CPU number, and the value is the size of the queue on that CPU (qsize). Redirect passes the packet to another CPU's kthread
// (`cpumap/<cpu>/map:<id>`), which puts it into the network stack on that CPU. **MaxEntries must be at most the number of possible CPUs** — gobpf.Load stops a larger declaration
// before load (cilium v0.22 silently shrinks it to the possible count). Creating the map needs CAP_BPF.
type CPUMap struct {
	// MaxEntries is the maximum number of CPUs (a nonzero constant — at most the number of possible CPUs).
	MaxEntries uint32
}

// DevMapHash is the declaration of a BPF_MAP_TYPE_DEVMAP_HASH: the key is any u32 (a hash key, not an index), and the value is the ifindex of the target interface.
// Creating the map needs CAP_NET_ADMIN. The ifindex caveat is the same as DevMap (looked up in the netns of the process that calls Set).
type DevMapHash struct {
	// MaxEntries is the maximum number of entries (a nonzero constant).
	MaxEntries uint32
}

// XSKMap is the declaration of a BPF_MAP_TYPE_XSKMAP: the key is an rx queue number, and the value is an AF_XDP socket fd (at Set — the kernel holds a reference to the socket).
// The socket must be bound to the frame's device and queue (the user's responsibility — a redirect to an unbound socket drops the packet).
// Creating the map needs CAP_NET_ADMIN.
type XSKMap struct {
	// MaxEntries is the maximum number of queues (a nonzero constant).
	MaxEntries uint32
}

// Redirect is eBPF side only: passes the packet to CPU k (the same shape as DevMap.Redirect — fallback if there is no entry).
func (m *CPUMap) Redirect(ctx *XDPContext, k uint32, fallback XDPAction) XDPAction {
	panic(ebpfOnly("CPUMap.Redirect"))
}

// RedirectIf is eBPF side only (the same shape as DevMap.RedirectIf).
func (m *CPUMap) RedirectIf(ctx *XDPContext, cond bool, k uint32, fallback, otherwise XDPAction) XDPAction {
	panic(ebpfOnly("CPUMap.RedirectIf"))
}

// Redirect is eBPF side only: requests a redirect of the packet to the interface at key k (the same shape as DevMap.Redirect).
func (m *DevMapHash) Redirect(ctx *XDPContext, k uint32, fallback XDPAction) XDPAction {
	panic(ebpfOnly("DevMapHash.Redirect"))
}

// RedirectIf is eBPF side only (the same shape as DevMap.RedirectIf).
func (m *DevMapHash) RedirectIf(ctx *XDPContext, cond bool, k uint32, fallback, otherwise XDPAction) XDPAction {
	panic(ebpfOnly("DevMapHash.RedirectIf"))
}

// Redirect is eBPF side only: passes the packet to the AF_XDP socket of queue k (the same shape as DevMap.Redirect).
func (m *XSKMap) Redirect(ctx *XDPContext, k uint32, fallback XDPAction) XDPAction {
	panic(ebpfOnly("XSKMap.Redirect"))
}

// RedirectIf is eBPF side only (the same shape as DevMap.RedirectIf).
func (m *XSKMap) RedirectIf(ctx *XDPContext, cond bool, k uint32, fallback, otherwise XDPAction) XDPAction {
	panic(ebpfOnly("XSKMap.RedirectIf"))
}

// Set is user space only: sets the queue size qsize for CPU cpu's entry (nonzero — the kernel rejects 0).
func (m *CPUMap) Set(cpu, qsize uint32) error { return mapPut(m, "CPUMap.Set", cpu, qsize) }

// Remove is user space only: deletes CPU cpu's entry.
func (m *CPUMap) Remove(cpu uint32) error { return mapRemove(m, "CPUMap.Remove", cpu) }

// Set is user space only: sets the target of key k to ifindex.
func (m *DevMapHash) Set(k, ifindex uint32) error { return mapPut(m, "DevMapHash.Set", k, ifindex) }

// Remove is user space only: deletes the entry at key k.
func (m *DevMapHash) Remove(k uint32) error { return mapRemove(m, "DevMapHash.Remove", k) }

// Set is user space only: puts an AF_XDP socket fd in queue's entry.
func (m *XSKMap) Set(queue uint32, fd int) error { return mapPut(m, "XSKMap.Set", queue, uint32(fd)) }

// Remove is user space only: deletes queue's entry.
func (m *XSKMap) Remove(queue uint32) error { return mapRemove(m, "XSKMap.Remove", queue) }

// GobpfTypes is an internal API of the gobpf runtime — the key and value are u32.
func (m *CPUMap) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfTypes is an internal API of the gobpf runtime — the key and value are u32.
func (m *DevMapHash) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfTypes is an internal API of the gobpf runtime — the key and value are u32.
func (m *XSKMap) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *CPUMap) GobpfMapKind() string { return "cpumap" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *DevMapHash) GobpfMapKind() string { return "devmap_hash" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *XSKMap) GobpfMapKind() string { return "xskmap" }
