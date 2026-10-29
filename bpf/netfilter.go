package bpf

// netfilter programs (bpf-mlir's netfilter kind):
//
//	func onNF(ctx *bpf.NetfilterContext) bpf.NFAction {
//		if ctx.SkbLen() > 1000 {
//			return bpf.NFDrop
//		}
//		return bpf.NFAccept
//	}
//
// There is no directive (the type decides the kind). Attach with gobpf.AttachNetfilter — it attaches to **the hook of the netns of the thread that creates the link** (gobpf attaches on a thread that
// setns'd into the given netns, and checks before attaching that it is not the host netns). Hook / PF are CO-RE reads of nf_hook_state fields, and SkbLen of an sk_buff field
// (behind a kernel pointer — the verifier needs CAP_PERFMON or CAP_SYS_ADMIN). There is no packet window. A non-root loader needs
// CAP_BPF + CAP_NET_ADMIN + CAP_PERFMON.

// NetfilterContext is the context of a netfilter program (struct bpf_nf_ctx — only reads through the state and skb kernel pointers).
type NetfilterContext struct{ _ [0]func() }

// NFAction is a netfilter verdict (the kernel's NF_DROP / NF_ACCEPT).
type NFAction uint32

// netfilter verdicts: NFDrop drops the packet (at LOCAL_OUT the send gets EPERM), NFAccept goes on to the next hook.
const (
	NFDrop   NFAction = 0 // NF_DROP
	NFAccept NFAction = 1 // NF_ACCEPT
)

// Hook is eBPF side only: the hook number (nf_hook_state.hook — PRE_ROUTING 0, LOCAL_IN 1, FORWARD 2, LOCAL_OUT 3, POST_ROUTING 4).
func (c *NetfilterContext) Hook() uint8 { panic(ebpfOnly("NetfilterContext.Hook")) }

// PF is eBPF side only: the protocol family (nf_hook_state.pf — IPv4 2, IPv6 10).
func (c *NetfilterContext) PF() uint8 { panic(ebpfOnly("NetfilterContext.PF")) }

// SkbLen is eBPF side only: the skb length (sk_buff.len — from the IP header at LOCAL_IN / LOCAL_OUT).
func (c *NetfilterContext) SkbLen() uint32 { panic(ebpfOnly("NetfilterContext.SkbLen")) }
