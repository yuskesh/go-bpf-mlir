package bpf

// sched_act (bpf-mlir's sched_act kind): programs for the tc act_bpf action.
//
//	func onAct(ctx *bpf.TCActContext) bpf.TCActAction {
//		ctx.SetMark(0x11)
//		if ctx.Len() < 60 {
//			return bpf.TCActShot
//		}
//		return bpf.TCActOK
//	}
//
// **go does not attach them** — a real attach to tc act_bpf (a netlink tc filter and action) is outside the scope (bpf-mlir has no attach row for it, and
// cilium v0.22 has no netlink tc). The program runs through the test run (BPF_PROG_TEST_RUN) of `objs.Program(fn)`. The ctx is the same `__sk_buff` as sched_cls:
// reading Len, writing SetMark and Check windows (read only). Loading needs CAP_NET_ADMIN (or CAP_SYS_ADMIN).

// TCActContext is the context of a sched_act program (struct __sk_buff). A function whose first parameter has this type is a sched_act program (no directive).
type TCActContext struct{ _ [0]func() }

// Check is eBPF side only: if the packet window [off, off+n) exists, returns a Window and true (the same shape as XDPContext.Check — read only).
func (c *TCActContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("TCActContext.Check"))
}

// Len is eBPF side only: the skb length (bytes).
func (c *TCActContext) Len() uint32 { panic(ebpfOnly("TCActContext.Len")) }

// SetMark is eBPF side only: writes the skb mark (in a test run it appears as the mark of the ctx_out __sk_buff).
func (c *TCActContext) SetMark(v uint32) { panic(ebpfOnly("TCActContext.SetMark")) }

// TCActAction is a sched_act verdict (tc's TC_ACT_* — pkt_cls.h).
type TCActAction int32

// sched_act verdicts (a subset of tc_act): TCActOK passes the packet, TCActShot drops it (adding to the act's drop count), TCActPipe goes on to the next action.
// redirect, reclassify and unspec cannot be written (outside bpf-mlir's scope).
const (
	TCActOK   TCActAction = 0 // TC_ACT_OK
	TCActShot TCActAction = 2 // TC_ACT_SHOT
	TCActPipe TCActAction = 3 // TC_ACT_PIPE
)
