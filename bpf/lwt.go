package bpf

// lwt_in / lwt_out / lwt_xmit programs (bpf-mlir's lwt_in / lwt_out / lwt_xmit kinds):
//
//	func onOut(ctx *bpf.LWTOutContext) bpf.LWTAction {
//		if w, ok := ctx.Check(0, 20); ok && w.U8(9) == 17 { // from the IP header (there is no Ethernet header)
//			return bpf.LWTDrop // a UDP send gets EPERM
//		}
//		return bpf.LWTOK
//	}
//
// There is no directive (the type decides the kind). It attaches as a route encap (gobpf.AttachLWTRoute — `<dst> dev <oif> encap bpf in / out / xmit`):
// lwt_in runs at the route lookup on receive, lwt_out at the route output, and lwt_xmit at xmit before the device. LWTDrop drops the packet with −EPERM
// (a local sendto gets EPERM). The packet window (Check) is read only, and data starts at the network header. The xmit redirect is not emitted.
// A non-root loader needs CAP_BPF + CAP_NET_ADMIN (load). Adding the route needs CAP_NET_ADMIN in the netns.

// LWTInContext is the context of an lwt_in program (struct __sk_buff).
type LWTInContext struct{ _ [0]func() }

// LWTOutContext is the context of an lwt_out program (struct __sk_buff).
type LWTOutContext struct{ _ [0]func() }

// LWTXmitContext is the context of an lwt_xmit program (struct __sk_buff).
type LWTXmitContext struct{ _ [0]func() }

// LWTAction is the lwt verdict (the kernel's enum bpf_ret_code).
type LWTAction uint32

// lwt verdicts: LWTOK goes to the route's next stage, and LWTDrop drops the packet (−EPERM).
const (
	LWTOK   LWTAction = 0 // BPF_OK
	LWTDrop LWTAction = 2 // BPF_DROP
)

// Len is eBPF side only: the skb length (from the network header).
func (c *LWTInContext) Len() uint32 { panic(ebpfOnly("LWTInContext.Len")) }

// Len is eBPF side only (the same as LWTInContext.Len).
func (c *LWTOutContext) Len() uint32 { panic(ebpfOnly("LWTOutContext.Len")) }

// Len is eBPF side only (the same as LWTInContext.Len).
func (c *LWTXmitContext) Len() uint32 { panic(ebpfOnly("LWTXmitContext.Len")) }

// Check is eBPF side only: the packet window [off, off+n) (the same shape as XDPContext.Check — read only, off is from the network header).
func (c *LWTInContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("LWTInContext.Check"))
}

// Check is eBPF side only (the same as LWTInContext.Check).
func (c *LWTOutContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("LWTOutContext.Check"))
}

// Check is eBPF side only (the same as LWTInContext.Check).
func (c *LWTXmitContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("LWTXmitContext.Check"))
}
