package bpf

import "reflect"

// DevMap is the declaration of a BPF_MAP_TYPE_DEVMAP: the key is an index (u32, 0..MaxEntries-1), and the value is **the ifindex of the target interface** (u32).
// Write it as a package-level variable; user space Sets the entries before attach:
//
//	var Ports = bpf.DevMap{MaxEntries: 8}
//
//	func Fwd(ctx *bpf.XDPContext) bpf.XDPAction {
//		…
//		return Ports.Redirect(ctx, k, bpf.XDPPass)
//	}
//
// **The ifindex is a value in the network namespace the program runs in (the netns of the attached interface)** — if you Set the ifindex of an interface in another netns,
// the kernel looks up the ifindex in the netns of the process that calls Set (see the examples/xdpfwd doc). There is no operation to read or write entries from the eBPF side
// (bpf-mlir rejects devmap lookup / update inside a program).
type DevMap struct {
	// MaxEntries is the number of indexes (a nonzero constant — written in the declaration's composite literal).
	MaxEntries uint32
}

// Redirect is eBPF side only: requests a redirect of the packet to the interface of index k's entry (helper bpf_redirect_map). **Write it only as the last statement of an xdp program body,
// `return M.Redirect(ctx, k, fallback)`.** If k's entry exists it returns XDP_REDIRECT; if not (unset, after Remove, or a k at or above
// MaxEntries) it returns fallback (a constant XDP verdict — not redirect). **The return value is the requested action, not whether delivery succeeded** — if the receiving side of the target veth
// has neither an XDP program nor GRO, the packet does not arrive.
func (m *DevMap) Redirect(ctx *XDPContext, k uint32, fallback XDPAction) XDPAction {
	panic(ebpfOnly("DevMap.Redirect"))
}

// RedirectIf is eBPF side only: if cond is true it is the same as Redirect(ctx, k, fallback); if false it returns otherwise (a constant) without requesting a redirect
// (bpf-mlir's `redirect_map … when %c else "<verdict>"`). Write it only as the last statement of the body, `return M.RedirectIf(ctx, cond, k, fallback, otherwise)`.
func (m *DevMap) RedirectIf(ctx *XDPContext, cond bool, k uint32, fallback, otherwise XDPAction) XDPAction {
	panic(ebpfOnly("DevMap.RedirectIf"))
}

// Set is user space only: sets the target of index k to ifindex. **The kernel rejects an ifindex that does not exist** (EINVAL — the kernel's devmap looks up the ifindex in the netns of the process that calls Set),
// and a k at or above MaxEntries is an error too.
func (m *DevMap) Set(k, ifindex uint32) error { return mapPut(m, "DevMap.Set", k, ifindex) }

// Get is user space only: the ifindex of index k (unset is an error).
func (m *DevMap) Get(k uint32) (uint32, error) { return mapGet[uint32, uint32](m, "DevMap.Get", k) }

// Remove is user space only: deletes index k's entry (later Redirects return fallback).
func (m *DevMap) Remove(k uint32) error { return mapRemove(m, "DevMap.Remove", k) }

// GobpfTypes is an internal API of the gobpf runtime (the same as Array.GobpfTypes) — the key and value are u32.
func (m *DevMap) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *DevMap) GobpfMapKind() string { return "devmap" }
