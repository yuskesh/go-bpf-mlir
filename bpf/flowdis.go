package bpf

// flow_dissector programs (bpf-mlir's flow_dissector kind, with flow_keys reads and writes):
//
//	func dissect(ctx *bpf.FlowDissectorContext) bpf.FlowAction {
//		if ctx.NProto() != 0x0008 { // the raw IPv4 ethertype (network-order 08 00 read as little endian)
//			return bpf.FlowContinue // hand back to the kernel's dissector
//		}
//		if w, ok := ctx.Check(14, 20); ok {
//			ctx.SetIPProto(w.U8(9))
//			ctx.SetThoff(34)
//			return bpf.FlowOK
//		}
//		return bpf.FlowDrop
//	}
//
// There is no directive (the type decides the kind). The program writes fields of the dissector output struct bpf_flow_keys with Set…, and on the FlowOK verdict the kernel
// uses those values as the flow key. Before the program, the kernel zeroes flow_keys and fills in NProto (the raw ethertype), Nhoff, Thoff (= Nhoff) and Flags;
// afterwards it clamps Nhoff to [original Nhoff, length] and Thoff to [Nhoff, length]. Network-order fields (NProto, AddrProto, Sport, Dport, IPv4Src,
// IPv4Dst, FlowLabel) keep the byte order (writing the value of a packet LE16 / LE32 read as is copies the bytes). The packet window (Check) is read only.
// Attach with gobpf.AttachNetNs (a netns link — one per netns). In a test run, data starts with the Ethernet header (Nhoff 14).
// A non-root loader needs CAP_BPF + CAP_NET_ADMIN (load). A window at a variable offset also needs CAP_PERFMON.

// FlowDissectorContext is the context of a flow_dissector program (struct __sk_buff — only the packet window and flow_keys).
type FlowDissectorContext struct{ _ [0]func() }

// FlowAction is the flow_dissector verdict (the kernel's enum bpf_ret_code).
type FlowAction uint32

// flow_dissector verdicts: FlowOK uses flow_keys as the flow key, FlowDrop is a dissect failure, and FlowContinue hands back to the kernel's dissector.
const (
	FlowOK       FlowAction = 0   // BPF_OK
	FlowDrop     FlowAction = 2   // BPF_DROP
	FlowContinue FlowAction = 129 // BPF_FLOW_DISSECTOR_CONTINUE
)

// Check is eBPF side only: the packet window [off, off+n) (the same shape as XDPContext.Check — read only).
func (c *FlowDissectorContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("FlowDissectorContext.Check"))
}

// Nhoff is eBPF side only: the network header offset (flow_keys.nhoff).
func (c *FlowDissectorContext) Nhoff() uint16 { panic(ebpfOnly("FlowDissectorContext.Nhoff")) }

// Thoff is eBPF side only: the transport header offset (flow_keys.thoff).
func (c *FlowDissectorContext) Thoff() uint16 { panic(ebpfOnly("FlowDissectorContext.Thoff")) }

// AddrProto is eBPF side only: the address ethertype (raw network order).
func (c *FlowDissectorContext) AddrProto() uint16 { panic(ebpfOnly("FlowDissectorContext.AddrProto")) }

// IsFrag is eBPF side only: 1 if it is a fragment.
func (c *FlowDissectorContext) IsFrag() uint8 { panic(ebpfOnly("FlowDissectorContext.IsFrag")) }

// IsFirstFrag is eBPF side only: 1 if it is the first fragment.
func (c *FlowDissectorContext) IsFirstFrag() uint8 {
	panic(ebpfOnly("FlowDissectorContext.IsFirstFrag"))
}

// IsEncap is eBPF side only: 1 if it is encapsulated.
func (c *FlowDissectorContext) IsEncap() uint8 { panic(ebpfOnly("FlowDissectorContext.IsEncap")) }

// IPProto is eBPF side only: the transport protocol (TCP 6, UDP 17).
func (c *FlowDissectorContext) IPProto() uint8 { panic(ebpfOnly("FlowDissectorContext.IPProto")) }

// NProto is eBPF side only: the network ethertype (raw network order — the kernel's input).
func (c *FlowDissectorContext) NProto() uint16 { panic(ebpfOnly("FlowDissectorContext.NProto")) }

// Sport is eBPF side only: the source port (raw network order).
func (c *FlowDissectorContext) Sport() uint16 { panic(ebpfOnly("FlowDissectorContext.Sport")) }

// Dport is eBPF side only: the destination port (raw network order).
func (c *FlowDissectorContext) Dport() uint16 { panic(ebpfOnly("FlowDissectorContext.Dport")) }

// IPv4Src is eBPF side only: the IPv4 source (raw network order).
func (c *FlowDissectorContext) IPv4Src() uint32 { panic(ebpfOnly("FlowDissectorContext.IPv4Src")) }

// IPv4Dst is eBPF side only: the IPv4 destination (raw network order).
func (c *FlowDissectorContext) IPv4Dst() uint32 { panic(ebpfOnly("FlowDissectorContext.IPv4Dst")) }

// Flags is eBPF side only: the kernel's input BPF_FLOW_DISSECTOR_F_* (PARSE_1ST_FRAG 1, STOP_AT_FLOW_LABEL 2, STOP_AT_ENCAP 4).
func (c *FlowDissectorContext) Flags() uint32 { panic(ebpfOnly("FlowDissectorContext.Flags")) }

// FlowLabel is eBPF side only: the IPv6 flow label (raw network order).
func (c *FlowDissectorContext) FlowLabel() uint32 { panic(ebpfOnly("FlowDissectorContext.FlowLabel")) }

// SetNhoff is eBPF side only: writes flow_keys.nhoff (the kernel clamps it afterwards).
func (c *FlowDissectorContext) SetNhoff(v uint16) { panic(ebpfOnly("FlowDissectorContext.SetNhoff")) }

// SetThoff is eBPF side only: writes flow_keys.thoff (the kernel clamps it afterwards).
func (c *FlowDissectorContext) SetThoff(v uint16) { panic(ebpfOnly("FlowDissectorContext.SetThoff")) }

// SetAddrProto is eBPF side only: writes flow_keys.addr_proto (raw network order).
func (c *FlowDissectorContext) SetAddrProto(v uint16) {
	panic(ebpfOnly("FlowDissectorContext.SetAddrProto"))
}

// SetIsFrag is eBPF side only: writes flow_keys.is_frag.
func (c *FlowDissectorContext) SetIsFrag(v uint8) { panic(ebpfOnly("FlowDissectorContext.SetIsFrag")) }

// SetIsFirstFrag is eBPF side only: writes flow_keys.is_first_frag.
func (c *FlowDissectorContext) SetIsFirstFrag(v uint8) {
	panic(ebpfOnly("FlowDissectorContext.SetIsFirstFrag"))
}

// SetIsEncap is eBPF side only: writes flow_keys.is_encap.
func (c *FlowDissectorContext) SetIsEncap(v uint8) {
	panic(ebpfOnly("FlowDissectorContext.SetIsEncap"))
}

// SetIPProto is eBPF side only: writes flow_keys.ip_proto.
func (c *FlowDissectorContext) SetIPProto(v uint8) {
	panic(ebpfOnly("FlowDissectorContext.SetIPProto"))
}

// SetNProto is eBPF side only: writes flow_keys.n_proto (raw network order).
func (c *FlowDissectorContext) SetNProto(v uint16) { panic(ebpfOnly("FlowDissectorContext.SetNProto")) }

// SetSport is eBPF side only: writes flow_keys.sport (raw network order).
func (c *FlowDissectorContext) SetSport(v uint16) { panic(ebpfOnly("FlowDissectorContext.SetSport")) }

// SetDport is eBPF side only: writes flow_keys.dport (raw network order).
func (c *FlowDissectorContext) SetDport(v uint16) { panic(ebpfOnly("FlowDissectorContext.SetDport")) }

// SetIPv4Src is eBPF side only: writes flow_keys.ipv4_src (raw network order).
func (c *FlowDissectorContext) SetIPv4Src(v uint32) {
	panic(ebpfOnly("FlowDissectorContext.SetIPv4Src"))
}

// SetIPv4Dst is eBPF side only: writes flow_keys.ipv4_dst (raw network order).
func (c *FlowDissectorContext) SetIPv4Dst(v uint32) {
	panic(ebpfOnly("FlowDissectorContext.SetIPv4Dst"))
}

// SetFlags is eBPF side only: writes flow_keys.flags.
func (c *FlowDissectorContext) SetFlags(v uint32) { panic(ebpfOnly("FlowDissectorContext.SetFlags")) }

// SetFlowLabel is eBPF side only: writes flow_keys.flow_label (raw network order).
func (c *FlowDissectorContext) SetFlowLabel(v uint32) {
	panic(ebpfOnly("FlowDissectorContext.SetFlowLabel"))
}
