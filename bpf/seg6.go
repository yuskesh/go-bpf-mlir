package bpf

// lwt_seg6local programs (bpf-mlir's lwt_seg6local kind):
//
//	func onSeg6(ctx *bpf.Seg6LocalContext) bpf.Seg6Action {
//		if ctx.Mark() == 17 {
//			ctx.SetMark(42) // the lookup after End.BPF follows the fwmark rules
//		}
//		return bpf.Seg6OK
//	}
//
// There is no directive (the type decides the kind). It attaches as the End.BPF action of a seg6local route (gobpf.AttachSeg6Local — `<sid>/128 dev <oif> encap
// seg6local action End.BPF`). Before the program, the kernel decrements the SRH's segments_left by 1 and sets the destination to the next segment. Seg6OK looks up the next segment
// and forwards; Seg6Drop drops the packet. The program does not run for a packet whose SRH has segments_left 0 (the kernel drops it first).
// **There is no test run** (the kernel has no test run for lwt_seg6local). The packet window, the seg6 helpers (store_bytes / adjust_srh / action) and the redirect verdict are
// not emitted (see limits). A non-root loader needs CAP_BPF + CAP_NET_ADMIN (load). Adding the route needs CAP_NET_ADMIN in the netns.

// Seg6LocalContext is the context of an lwt_seg6local program (struct __sk_buff).
type Seg6LocalContext struct{ _ [0]func() }

// Seg6Action is the verdict of lwt_seg6local (the kernel's enum bpf_ret_code).
type Seg6Action uint32

// lwt_seg6local verdicts: Seg6OK looks up and forwards to the next segment, and Seg6Drop drops the packet.
const (
	Seg6OK   Seg6Action = 0 // BPF_OK
	Seg6Drop Seg6Action = 2 // BPF_DROP
)

// Len is eBPF side only: the skb length (from the IPv6 header).
func (c *Seg6LocalContext) Len() uint32 { panic(ebpfOnly("Seg6LocalContext.Len")) }

// Mark is eBPF side only: the skb mark.
func (c *Seg6LocalContext) Mark() uint32 { panic(ebpfOnly("Seg6LocalContext.Mark")) }

// SetMark is eBPF side only: writes the skb mark (it affects the fwmark of the lookup after End.BPF).
func (c *Seg6LocalContext) SetMark(v uint32) { panic(ebpfOnly("Seg6LocalContext.SetMark")) }

// Priority is eBPF side only: the skb priority.
func (c *Seg6LocalContext) Priority() uint32 { panic(ebpfOnly("Seg6LocalContext.Priority")) }

// SetPriority is eBPF side only: writes the skb priority.
func (c *Seg6LocalContext) SetPriority(v uint32) { panic(ebpfOnly("Seg6LocalContext.SetPriority")) }

// Protocol is eBPF side only: the skb protocol (the ethertype as a be16 — IPv6 is 0xdd86 on a little-endian host).
func (c *Seg6LocalContext) Protocol() uint32 { panic(ebpfOnly("Seg6LocalContext.Protocol")) }

// Ifindex is eBPF side only: the ifindex of the skb's device (the receiving device).
func (c *Seg6LocalContext) Ifindex() uint32 { panic(ebpfOnly("Seg6LocalContext.Ifindex")) }
