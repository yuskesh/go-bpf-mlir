package bpf

// sk_lookup programs (bpf-mlir's sk_lookup kind):
//
//	func onLookup(ctx *bpf.SkLookupContext) bpf.SKAction {
//		if ctx.Protocol() == 6 && ctx.LocalPort() == 7001 {
//			return bpf.SKDrop // a TCP connect to 7001 gets ECONNREFUSED
//		}
//		return bpf.SKPass // the normal lookup
//	}
//
// There is no directive (the type decides the kind). Attach with gobpf.AttachNetNs — **it runs only on lookups of TCP listeners and UDP sockets in the attached netns**
// (TCP on SYN, UDP on a datagram to an unconnected socket — it also runs on the lookup of the sender of an error ICMP). SKDrop turns the lookup into
// "no socket" (TCP gets RST, UDP gets ICMP port unreachable). There is no sk_assign to select a socket (bpf-mlir has no op for it — see limits).
// A non-root loader needs CAP_BPF (load).

// SkLookupContext is the context of an sk_lookup program (struct bpf_sk_lookup, read only).
type SkLookupContext struct{ _ [0]func() }

// Family is eBPF side only: the address family (AF_INET 2, AF_INET6 10).
func (c *SkLookupContext) Family() uint32 { panic(ebpfOnly("SkLookupContext.Family")) }

// Protocol is eBPF side only: the IP protocol (TCP 6, UDP 17).
func (c *SkLookupContext) Protocol() uint32 { panic(ebpfOnly("SkLookupContext.Protocol")) }

// LocalIP4 is eBPF side only: the destination IPv4 address (**network order** — 127.0.0.1 is 0x0100007F as a little-endian uint32).
func (c *SkLookupContext) LocalIP4() uint32 { panic(ebpfOnly("SkLookupContext.LocalIP4")) }

// LocalPort is eBPF side only: the destination port (**host order**).
func (c *SkLookupContext) LocalPort() uint32 { panic(ebpfOnly("SkLookupContext.LocalPort")) }

// RemotePort is eBPF side only: the sender's port (**a network-order be16** — the kernel's __be16 as is, not converted on the Go side: port 7201 is 0x211C).
func (c *SkLookupContext) RemotePort() uint16 { panic(ebpfOnly("SkLookupContext.RemotePort")) }
