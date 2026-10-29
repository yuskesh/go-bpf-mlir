package bpf

// cgroup_sockopt programs (bpf-mlir's cgroup_sockopt kind, with optval writes):
//
//	func onSet(ctx *bpf.CgroupSetsockoptContext) bpf.CgroupAction {
//		if ctx.Level() == 1 && ctx.Optname() == 12 { // SOL_SOCKET / SO_PRIORITY
//			if w, ok := ctx.Check(0, 4); ok {
//				w.SetLE32(0, 5) // make the value passed to the handler 5
//			}
//		}
//		return bpf.CgroupAllow
//	}
//
// The direction is the type (no directive): CgroupSetsockoptContext runs **before the kernel's handler** of setsockopt, and CgroupGetsockoptContext runs **after the handler**
// of getsockopt (optval is a copy of the value the handler returned — writes are visible to the user). Attach with gobpf.AttachCgroup — **only the programs of the cgroup of the task
// that created the socket run**. CgroupDeny makes the syscall fail with EPERM. Writes to the optval window (Check) are only at the top level of the program body (not inside loops,
// not in subprograms). A non-root loader needs CAP_BPF + CAP_NET_ADMIN.

// CgroupSetsockoptContext is the context of a cgroup_sockopt program for setsockopt (struct bpf_sockopt).
type CgroupSetsockoptContext struct{ _ [0]func() }

// CgroupGetsockoptContext is the context of a cgroup_sockopt program for getsockopt (struct bpf_sockopt).
type CgroupGetsockoptContext struct{ _ [0]func() }

// Level is eBPF side only: the option level (SOL_SOCKET 1, etc.).
func (c *CgroupSetsockoptContext) Level() int32 { panic(ebpfOnly("CgroupSetsockoptContext.Level")) }

// Optname is eBPF side only: the option name (SO_PRIORITY 12, etc.).
func (c *CgroupSetsockoptContext) Optname() int32 { panic(ebpfOnly("CgroupSetsockoptContext.Optname")) }

// Optlen is eBPF side only: the length of the optval the user passed.
func (c *CgroupSetsockoptContext) Optlen() int32 { panic(ebpfOnly("CgroupSetsockoptContext.Optlen")) }

// SetOptlen is eBPF side only: the length passed to the handler — −1 skips the handler (the syscall returns 0), 0 passes the user's original value, other values pass the window's value with that length.
func (c *CgroupSetsockoptContext) SetOptlen(v int32) {
	panic(ebpfOnly("CgroupSetsockoptContext.SetOptlen"))
}

// Check is eBPF side only: the optval window [off, off+n) (the window length is max(16, optlen) bytes — the same shape as XDPContext.Check, read and write).
func (c *CgroupSetsockoptContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("CgroupSetsockoptContext.Check"))
}

// Level is eBPF side only (the same as CgroupSetsockoptContext.Level).
func (c *CgroupGetsockoptContext) Level() int32 { panic(ebpfOnly("CgroupGetsockoptContext.Level")) }

// Optname is eBPF side only (the same as CgroupSetsockoptContext.Optname).
func (c *CgroupGetsockoptContext) Optname() int32 { panic(ebpfOnly("CgroupGetsockoptContext.Optname")) }

// Optlen is eBPF side only: the length the handler returned (if the handler failed, the length the user passed).
func (c *CgroupGetsockoptContext) Optlen() int32 { panic(ebpfOnly("CgroupGetsockoptContext.Optlen")) }

// SetOptlen is eBPF side only: the length returned to the user — 0 keeps the handler's result (no copy back); a negative value or one above the user's length gives EFAULT.
func (c *CgroupGetsockoptContext) SetOptlen(v int32) {
	panic(ebpfOnly("CgroupGetsockoptContext.SetOptlen"))
}

// Check is eBPF side only: the optval window [off, off+n) (the window length is the length the user passed — read and write; writes are visible to the user).
func (c *CgroupGetsockoptContext) Check(off uint32, n uint32) (Window, bool) {
	panic(ebpfOnly("CgroupGetsockoptContext.Check"))
}
