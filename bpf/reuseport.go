package bpf

import "reflect"

// sk_reuseport and reuseport_sockarray (bpf-mlir's sk_reuseport kind and reuseport_sockarray map kind):
//
//	var Socks = bpf.ReuseportSockArray{MaxEntries: 4}
//
//	func onSelect(ctx *bpf.SkReuseportContext) bpf.SKAction {
//		if st := Socks.Select(ctx, 1); st != 0 { // select the socket at key 1 (raw status — an empty slot gives −ENOENT)
//			return bpf.SKPass // a pass without selecting is the kernel's hash selection
//		}
//		return bpf.SKPass
//	}
//
// There is no directive (the type decides the kind). Attach with gobpf.AttachReuseport (setsockopt SO_ATTACH_REUSEPORT_EBPF on a socket — it runs only for selection in the attached socket's
// SO_REUSEPORT group; attach after bind). User space puts the group's sockets in the map with Set (only bound SO_REUSEPORT sockets).
// SKDrop delivers the datagram to no one (a TCP SYN gets ECONNREFUSED). When every socket of the group is closed, the slots disappear and the group releases the program.
// A non-root loader needs only CAP_BPF (SK_REUSEPORT is outside the kernel's is_net_admin_prog_type).

// SkReuseportContext is the context of an sk_reuseport program (struct sk_reuseport_md — read only).
type SkReuseportContext struct{ _ [0]func() }

// Len is eBPF side only: the skb length (for UDP, the 8-byte header + payload).
func (c *SkReuseportContext) Len() uint32 { panic(ebpfOnly("SkReuseportContext.Len")) }

// EthProtocol is eBPF side only: the skb protocol (**as a be16** — IPv4's 0x0800 is 8 as a little-endian uint32).
func (c *SkReuseportContext) EthProtocol() uint32 { panic(ebpfOnly("SkReuseportContext.EthProtocol")) }

// IPProtocol is eBPF side only: the protocol of the group's sockets (UDP 17, TCP 6).
func (c *SkReuseportContext) IPProtocol() uint32 { panic(ebpfOnly("SkReuseportContext.IPProtocol")) }

// BindInany is eBPF side only: 1 if the group is bound to the wildcard address (0.0.0.0 / ::).
func (c *SkReuseportContext) BindInany() uint32 { panic(ebpfOnly("SkReuseportContext.BindInany")) }

// Hash is eBPF side only: the 4-tuple hash (depends on the kernel's random secret).
func (c *SkReuseportContext) Hash() uint32 { panic(ebpfOnly("SkReuseportContext.Hash")) }

// ReuseportSockArray is the declaration of a BPF_MAP_TYPE_REUSEPORT_SOCKARRAY: the key is a u32 in 0..MaxEntries−1, and the value is a socket (the fd from Set — reads give the socket's
// cookie as a u64). The eBPF side has only Select (the kernel verifier refuses lookup / update).
type ReuseportSockArray struct {
	// MaxEntries is the maximum number of entries (a nonzero constant).
	MaxEntries uint32
}

// Select is eBPF side only: selects the socket at key k as the group's receiver and returns the helper's raw status (0; −ENOENT for an empty slot or out of range; −EBADFD and others for a socket
// of another group — only in an sk_reuseport program body, outside loops). Return the SKPass verdict even after selecting.
func (m *ReuseportSockArray) Select(ctx *SkReuseportContext, k uint32) int64 {
	panic(ebpfOnly("ReuseportSockArray.Select"))
}

// Set is user space only: puts a socket fd at key k (only a bound SO_REUSEPORT UDP socket or a TCP listener — others give EINVAL / ENOTSUPP).
func (m *ReuseportSockArray) Set(k uint32, fd int) error {
	return mapPut(m, "ReuseportSockArray.Set", k, uint64(fd))
}

// Cookie is user space only: the cookie of the socket at key k (an empty slot gives ErrKeyNotExist — the slot disappears when the group's socket is closed).
func (m *ReuseportSockArray) Cookie(k uint32) (uint64, error) {
	return mapGet[uint32, uint64](m, "ReuseportSockArray.Cookie", k)
}

// Remove is user space only: deletes the entry at key k.
func (m *ReuseportSockArray) Remove(k uint32) error {
	return mapRemove(m, "ReuseportSockArray.Remove", k)
}

// GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is a u64 (socket fd / cookie).
func (m *ReuseportSockArray) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint64]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *ReuseportSockArray) GobpfMapKind() string { return "reuseport_sockarray" }
