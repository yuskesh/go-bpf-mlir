package bpf

import "reflect"

// sockmap, sockhash and sk_skb (bpf-mlir's sockmap / sockhash maps and sk_skb kind):
//
//	var Socks = bpf.SockMap{MaxEntries: 2}
//
//	//gobpf:sk_skb Socks                      ← the name of the sockmap / sockhash variable to attach to
//	func onSKB(ctx *bpf.SKSKBContext) bpf.SKAction {
//		return Socks.RedirectIf(ctx, ctx.Len() == 7, 1, bpf.SKIngress, bpf.SKPass)
//	}
//
// sk_skb (stream_verdict) runs on received skbs of TCP sockets in the map. The verdicts are SKPass (to the receiving socket) and SKDrop (drop); Redirect
// moves it to another socket (only as a top-level return of the body — the same rules as DevMap.RedirectIf, with the helper's value as the return value: SK_PASS if the key's socket exists,
// SK_DROP if not. The redirect is asynchronous on a work queue — the return value is acceptance of the request, not whether delivery succeeded). User space puts sockets in with Set (the kernel
// accepts only TCP ESTABLISHED / LISTEN, etc.). Attach with gobpf.AttachSockmap (PROG_ATTACH — detached when the map goes away). Creating the map and loading the program need
// CAP_NET_ADMIN.

// SockMap is the declaration of a BPF_MAP_TYPE_SOCKMAP: the key is a u32 in 0..MaxEntries−1, and the value is a socket (the fd from Set — the kernel holds a reference to the socket).
type SockMap struct {
	// MaxEntries is the maximum number of entries (a nonzero constant).
	MaxEntries uint32
}

// SockHash is the declaration of a BPF_MAP_TYPE_SOCKHASH: the key is any K (an integer), and the value is a socket.
type SockHash[K KprobeInt] struct {
	// MaxEntries is the maximum number of entries (a nonzero constant).
	MaxEntries uint32
}

// SKSKBContext is the context of an sk_skb program (struct __sk_buff — only Len and LocalPort are readable). The directive `//gobpf:sk_skb <map>` decides the attach target.
type SKSKBContext struct{ _ [0]func() }

// Len is eBPF side only: the skb length (bytes).
func (c *SKSKBContext) Len() uint32 { panic(ebpfOnly("SKSKBContext.Len")) }

// LocalPort is eBPF side only: the local port of the receiving socket (host byte order).
func (c *SKSKBContext) LocalPort() uint32 { panic(ebpfOnly("SKSKBContext.LocalPort")) }

// SKAction is the sk_skb verdict (the kernel's enum sk_action).
type SKAction uint32

// sk_skb verdicts (the same values as the UAPI enum sk_action): SKDrop drops the skb, and SKPass goes to the receiving socket. Only the return value of Redirect / RedirectIf gives a redirect.
const (
	SKDrop SKAction = 0 // SK_DROP
	SKPass SKAction = 1 // SK_PASS
)

// SKDirection is the redirect direction (whether BPF_F_INGRESS is set).
type SKDirection uint32

// Redirect directions: SKEgress sends from the target socket, and SKIngress puts it into the target socket's receive path (BPF_F_INGRESS).
const (
	SKEgress  SKDirection = 0
	SKIngress SKDirection = 1
)

// Redirect is eBPF side only: moves the skb to the socket at key k (the direction is a constant — only as a top-level return of the body).
func (m *SockMap) Redirect(ctx *SKSKBContext, k uint32, dir SKDirection) SKAction {
	panic(ebpfOnly("SockMap.Redirect"))
}

// RedirectIf is eBPF side only: Redirect if cond, otherwise otherwise (a constant verdict).
func (m *SockMap) RedirectIf(ctx *SKSKBContext, cond bool, k uint32, dir SKDirection, otherwise SKAction) SKAction {
	panic(ebpfOnly("SockMap.RedirectIf"))
}

// Redirect is eBPF side only (the same as SockMap.Redirect — the key is K).
func (m *SockHash[K]) Redirect(ctx *SKSKBContext, k K, dir SKDirection) SKAction {
	panic(ebpfOnly("SockHash.Redirect"))
}

// RedirectIf is eBPF side only (the same as SockMap.RedirectIf — the key is K).
func (m *SockHash[K]) RedirectIf(ctx *SKSKBContext, cond bool, k K, dir SKDirection, otherwise SKAction) SKAction {
	panic(ebpfOnly("SockHash.RedirectIf"))
}

// sk_msg and insertion from sock_ops (bpf-mlir's sk_msg kind and sock_ops map update):
//
//	//gobpf:sk_msg Socks
//	func onMsg(ctx *bpf.SKMsgContext) bpf.SKAction {
//		return Socks.MsgRedirectIf(ctx, ctx.Size() == 7, 1, bpf.SKIngress, bpf.SKPass)
//	}
//
// sk_msg runs on sent (sendmsg) messages of sockets in the map. SKDrop drops the message and sendmsg gives EACCES (when 0 bytes were sent);
// MsgRedirect goes to another socket (ingress puts it into the receive path, egress sends from the target socket — egress only to TCP targets). A sock_ops program
// puts the callback's socket in the map with `st := Socks.Insert(ctx, k, bpf.SockAny)` (only ESTABLISHED / LISTEN callbacks — others give −EOPNOTSUPP).

// SKMsgContext is the context of an sk_msg program (struct sk_msg_md — read only). The directive `//gobpf:sk_msg <map>` decides the attach target.
type SKMsgContext struct{ _ [0]func() }

// Size is eBPF side only: the number of bytes in the message.
func (c *SKMsgContext) Size() uint32 { panic(ebpfOnly("SKMsgContext.Size")) }

// Family is eBPF side only: the socket's address family (AF_INET 2, AF_INET6 10).
func (c *SKMsgContext) Family() uint32 { panic(ebpfOnly("SKMsgContext.Family")) }

// RemoteIP4 is eBPF side only: the peer's IPv4 address (a u32 in network byte order as is — 127.0.0.1 reads as 0x0100007f in little endian).
func (c *SKMsgContext) RemoteIP4() uint32 { panic(ebpfOnly("SKMsgContext.RemoteIP4")) }

// LocalIP4 is eBPF side only: the local IPv4 address (the same byte order as RemoteIP4).
func (c *SKMsgContext) LocalIP4() uint32 { panic(ebpfOnly("SKMsgContext.LocalIP4")) }

// RemotePort is eBPF side only: the peer's port — **as the kernel converts it**: the 16 bits in network byte order shifted left by 16 bits
// (port 8080 is htons(8080) << 16).
func (c *SKMsgContext) RemotePort() uint32 { panic(ebpfOnly("SKMsgContext.RemotePort")) }

// LocalPort is eBPF side only: the local port (host byte order).
func (c *SKMsgContext) LocalPort() uint32 { panic(ebpfOnly("SKMsgContext.LocalPort")) }

// MsgRedirect is eBPF side only: moves the message to the socket at key k (the direction is a constant — only as a top-level return of the body).
func (m *SockMap) MsgRedirect(ctx *SKMsgContext, k uint32, dir SKDirection) SKAction {
	panic(ebpfOnly("SockMap.MsgRedirect"))
}

// MsgRedirectIf is eBPF side only: MsgRedirect if cond, otherwise otherwise (a constant verdict).
func (m *SockMap) MsgRedirectIf(ctx *SKMsgContext, cond bool, k uint32, dir SKDirection, otherwise SKAction) SKAction {
	panic(ebpfOnly("SockMap.MsgRedirectIf"))
}

// MsgRedirect is eBPF side only (the same as SockMap.MsgRedirect — the key is K).
func (m *SockHash[K]) MsgRedirect(ctx *SKMsgContext, k K, dir SKDirection) SKAction {
	panic(ebpfOnly("SockHash.MsgRedirect"))
}

// MsgRedirectIf is eBPF side only (the same as SockMap.MsgRedirectIf — the key is K).
func (m *SockHash[K]) MsgRedirectIf(ctx *SKMsgContext, cond bool, k K, dir SKDirection, otherwise SKAction) SKAction {
	panic(ebpfOnly("SockHash.MsgRedirectIf"))
}

// SockFlags is the flags of Insert (BPF_ANY / BPF_NOEXIST / BPF_EXIST).
type SockFlags uint32

// Insert flags: SockAny inserts whether or not the key exists, SockNoExist only for a missing key (−EEXIST if present), SockExist only for an existing key.
const (
	SockAny     SockFlags = 0
	SockNoExist SockFlags = 1
	SockExist   SockFlags = 2
)

// Insert is eBPF side only: puts the sock_ops callback's socket at key k and returns the helper's raw status (0 or a negative errno) (sock_ops programs only —
// outside loop bodies, flags is a constant).
func (m *SockMap) Insert(ctx *SockOpsContext, k uint32, flags SockFlags) int64 {
	panic(ebpfOnly("SockMap.Insert"))
}

// Insert is eBPF side only (the same as SockMap.Insert — the key is K).
func (m *SockHash[K]) Insert(ctx *SockOpsContext, k K, flags SockFlags) int64 {
	panic(ebpfOnly("SockHash.Insert"))
}

// SkAssignFlags is the flags of Assign (sklookupflag in bpf-mlir's UAPI table — constants only, combinable with `|`).
type SkAssignFlags uint32

// Assign flags: SkAssignReplace replaces the socket chosen by a previous program (or a previous Assign of the same program) (−EEXIST without it),
// and SkAssignNoReuseport skips reselection within the chosen socket's reuseport group.
const (
	SkAssignReplace     SkAssignFlags = 1 // BPF_SK_LOOKUP_F_REPLACE
	SkAssignNoReuseport SkAssignFlags = 2 // BPF_SK_LOOKUP_F_NO_REUSEPORT
)

// Assign is eBPF side only (an sk_lookup program body — bpf-mlir's ebpf.sk.assign): looks up the socket in slot k,
// and if present (found = true) selects it as the result of this lookup and releases the reference (the frontend assembles lookup, check, select and release — the reference never reaches Go). st is
// the raw status of helper sk_assign — 0 means selected, a negative errno means not selected (protocol mismatch −EPROTOTYPE, family mismatch −EAFNOSUPPORT, a refcounted
// socket (ESTABLISHED TCP, etc.) −ESOCKTNOSUPPORT, already selected without SkAssignReplace −EEXIST). An empty slot gives (0, false). flags is a constant.
// A statement that discards st is stopped by the frontend (GB017 — an explicit `_, _ =` is accepted). It cannot be placed inside a loop.
func (m *SockMap) Assign(ctx *SkLookupContext, k uint32, flags SkAssignFlags) (st int64, found bool) {
	panic(ebpfOnly("SockMap.Assign"))
}

// Assign is eBPF side only: the same as SockMap.Assign (the key is K).
func (m *SockHash[K]) Assign(ctx *SkLookupContext, k K, flags SkAssignFlags) (st int64, found bool) {
	panic(ebpfOnly("SockHash.Assign"))
}

// Set is user space only: puts a socket fd at key k (kernel errnos — EOPNOTSUPP for an unconnected TCP socket, ENOTSOCK for an fd that is not a socket).
func (m *SockMap) Set(k uint32, fd int) error { return mapPut(m, "SockMap.Set", k, uint32(fd)) }

// Remove is user space only: deletes the entry at key k.
func (m *SockMap) Remove(k uint32) error { return mapRemove(m, "SockMap.Remove", k) }

// Set is user space only: puts a socket fd at key k.
func (m *SockHash[K]) Set(k K, fd int) error { return mapPut(m, "SockHash.Set", k, uint32(fd)) }

// Remove is user space only: deletes the entry at key k.
func (m *SockHash[K]) Remove(k K) error { return mapRemove(m, "SockHash.Remove", k) }

// GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is a u32 (a socket fd).
func (m *SockMap) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfTypes is an internal API of the gobpf runtime — the key is K and the value is a u32 (a socket fd).
func (m *SockHash[K]) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[K](), reflect.TypeFor[uint32]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *SockMap) GobpfMapKind() string { return "sockmap" }

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *SockHash[K]) GobpfMapKind() string { return "sockhash" }
