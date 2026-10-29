package bpf

// Socket and cgroup programs (bpf-mlir's socket_filter, cgroup_skb, cgroup_sock, cgroup_sock_addr and sock_ops).
//
// Context fields are methods (reads are uint32, writes are Set…). **The kernel decides which fields each hook can read / write** (bpf-mlir's context access table —
// facts from load probes on 7.1.8) — a pair not in the table (for example Type at sock_release, UserIP4 at an inet6 hook) is stopped by the frontend with the named error GB008. Values are
// the kernel struct's as is (byte order is not changed — user_port and remote_port are network order, src_port and local_port are host order).
// The 4 cgroup kinds attach with gobpf.AttachCgroup (a cgroup v2 directory), and socket_filter attaches with gobpf.AttachSocketFilter (a socket fd).

// CgroupAction is the verdict of cgroup-family programs (the kernel verifier limits the return value to 0..1).
type CgroupAction int32

// cgroup-family verdicts (CgroupDeny makes connect() and similar calls fail with EPERM and drops cgroup_skb packets; CgroupAllow allows).
const (
	CgroupDeny  CgroupAction = 0
	CgroupAllow CgroupAction = 1
)

// SocketFilterAction is the verdict of a socket_filter program (the kernel's sk_filter_trim_cap — 0 drops, the u32 maximum accepts all bytes).
type SocketFilterAction int32

// socket_filter verdicts (SocketDrop drops the packet, SocketKeep accepts all bytes — the u32 maximum).
const (
	SocketDrop SocketFilterAction = 0
	SocketKeep SocketFilterAction = -1
)

// SocketFilterContext is the context of a socket_filter (SO_ATTACH_BPF — attached to a socket) program (struct __sk_buff). The verdict is SocketFilterAction.
type SocketFilterContext struct{ _ [0]func() }

// Len is eBPF side only: the packet length (__sk_buff's len).
func (c *SocketFilterContext) Len() uint32 { panic(ebpfOnly("SocketFilterContext.Len")) }

// CgroupSKBIngressContext is the context of a cgroup_skb ingress (packets entering the cgroup) program (struct __sk_buff). The verdict is CgroupAction.
type CgroupSKBIngressContext struct{ _ [0]func() }

// CgroupSKBEgressContext is the context of a cgroup_skb egress (packets leaving the cgroup) program. The verdict is CgroupAction (Deny makes the send fail with EPERM).
type CgroupSKBEgressContext struct{ _ [0]func() }

// Len is eBPF side only: the packet length (__sk_buff's len — from L3).
func (c *CgroupSKBIngressContext) Len() uint32 { panic(ebpfOnly("CgroupSKBIngressContext.Len")) }

// Len is eBPF side only (the same as CgroupSKBIngressContext.Len).
func (c *CgroupSKBEgressContext) Len() uint32 { panic(ebpfOnly("CgroupSKBEgressContext.Len")) }

// Check is eBPF side only: the packet window [off, off+n) (the same shape as XDPContext.Check — read only. cgroup_skb packets start at the L3 header).
func (c *CgroupSKBIngressContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("CgroupSKBIngressContext.Check"))
}

// Check is eBPF side only (the same as CgroupSKBIngressContext.Check).
func (c *CgroupSKBEgressContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("CgroupSKBEgressContext.Check"))
}

// CgroupSockContext is the context of a cgroup_sock program (struct bpf_sock). The hook is the directive
// `//gobpf:cgroup_sock <sock_create|sock_release|post_bind4|post_bind6>`. The verdict is CgroupAction (Deny at sock_create makes socket() fail with EPERM).
type CgroupSockContext struct{ _ [0]func() }

// Family is eBPF side only: the address family (AF_INET 2, AF_INET6 10).
func (c *CgroupSockContext) Family() uint32 { panic(ebpfOnly("CgroupSockContext.Family")) }

// Type is eBPF side only: the socket type (sock_create only).
func (c *CgroupSockContext) Type() uint32 { panic(ebpfOnly("CgroupSockContext.Type")) }

// Protocol is eBPF side only: the protocol.
func (c *CgroupSockContext) Protocol() uint32 { panic(ebpfOnly("CgroupSockContext.Protocol")) }

// SrcIP4 is eBPF side only: the bound IPv4 address (network order — post_bind4 only).
func (c *CgroupSockContext) SrcIP4() uint32 { panic(ebpfOnly("CgroupSockContext.SrcIP4")) }

// SrcPort is eBPF side only: the bound port (host order — post_bind4 / post_bind6 only).
func (c *CgroupSockContext) SrcPort() uint32 { panic(ebpfOnly("CgroupSockContext.SrcPort")) }

// SetMark is eBPF side only: the socket mark (SO_MARK — sock_create only).
func (c *CgroupSockContext) SetMark(v uint32) { panic(ebpfOnly("CgroupSockContext.SetMark")) }

// SockAddrContext is the context of a cgroup_sock_addr program (struct bpf_sock_addr). The hook is the directive
// `//gobpf:cgroup_sock_addr <bind4|connect4|sendmsg4|recvmsg4|getpeername4|getsockname4|bind6|connect6|sendmsg6|recvmsg6|getpeername6|getsockname6>`.
// The verdict is CgroupAction (recvmsg, getpeername and getsockname allow Allow only — the kernel limits the return value to 1).
type SockAddrContext struct{ _ [0]func() }

// Family is eBPF side only: the address family.
func (c *SockAddrContext) Family() uint32 { panic(ebpfOnly("SockAddrContext.Family")) }

// Type is eBPF side only: the socket type (connect4 only).
func (c *SockAddrContext) Type() uint32 { panic(ebpfOnly("SockAddrContext.Type")) }

// Protocol is eBPF side only: the protocol.
func (c *SockAddrContext) Protocol() uint32 { panic(ebpfOnly("SockAddrContext.Protocol")) }

// UserIP4 is eBPF side only: the IPv4 address the user passed (network order — inet4 / udp4 hooks only).
func (c *SockAddrContext) UserIP4() uint32 { panic(ebpfOnly("SockAddrContext.UserIP4")) }

// UserPort is eBPF side only: the port the user passed (network order — the low 16 bits).
func (c *SockAddrContext) UserPort() uint32 { panic(ebpfOnly("SockAddrContext.UserPort")) }

// SetUserIP4 is eBPF side only: rewrites the address (network order — inet4 / udp4 hooks only).
func (c *SockAddrContext) SetUserIP4(v uint32) { panic(ebpfOnly("SockAddrContext.SetUserIP4")) }

// SetUserPort is eBPF side only: rewrites the port (network order).
func (c *SockAddrContext) SetUserPort(v uint32) { panic(ebpfOnly("SockAddrContext.SetUserPort")) }

// SockOpsContext is the context of a sock_ops (callbacks for TCP socket operations — attached to a cgroup) program (struct bpf_sock_ops). The verdict is CgroupAction.
type SockOpsContext struct{ _ [0]func() }

// Op is eBPF side only: the callback kind (BPF_SOCK_OPS_TCP_CONNECT_CB 3, ACTIVE_ESTABLISHED_CB 4, PASSIVE_ESTABLISHED_CB 5, etc.).
func (c *SockOpsContext) Op() uint32 { panic(ebpfOnly("SockOpsContext.Op")) }

// Family is eBPF side only: the address family.
func (c *SockOpsContext) Family() uint32 { panic(ebpfOnly("SockOpsContext.Family")) }

// RemotePort is eBPF side only: the peer's port (network order in the upper 16 bits — as in the kernel's table).
func (c *SockOpsContext) RemotePort() uint32 { panic(ebpfOnly("SockOpsContext.RemotePort")) }

// LocalPort is eBPF side only: the local port (host order).
func (c *SockOpsContext) LocalPort() uint32 { panic(ebpfOnly("SockOpsContext.LocalPort")) }

// SetReply is eBPF side only: the callback's reply (its meaning depends on op — for example the RTO for TIMEOUT_INIT).
func (c *SockOpsContext) SetReply(v uint32) { panic(ebpfOnly("SockOpsContext.SetReply")) }
