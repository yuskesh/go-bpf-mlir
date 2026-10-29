package bpf

// cgroup_sysctl programs (bpf-mlir's cgroup_sysctl kind and ebpf.sysctl.set_new_value):
//
//	func onSysctl(ctx *bpf.CgroupSysctlContext) bpf.CgroupAction {
//		if ctx.Write() != 0 {
//			ctx.SetNewValue("63\n") // replaces the written value (raw status: 0 or a negative errno)
//		}
//		return bpf.CgroupAllow
//	}
//
// There is no directive (the type decides the kind). Attach with gobpf.AttachCgroup — **it runs only when a task in the attached cgroup (or a child cgroup) reads or writes a
// /proc/sys file**. CgroupDeny makes the read or write fail with EPERM. SetNewValue returns 0 **only on a write call** (−EINVAL on a read call), and
// the write(2) whose value was replaced returns the length of the replacement. A non-root loader needs CAP_BPF + CAP_NET_ADMIN.

// CgroupSysctlContext is the context of a cgroup_sysctl program (struct bpf_sysctl).
type CgroupSysctlContext struct{ _ [0]func() }

// Write is eBPF side only: 1 for a write call, 0 for a read.
func (c *CgroupSysctlContext) Write() uint32 { panic(ebpfOnly("CgroupSysctlContext.Write")) }

// FilePos is eBPF side only: the file position (the read or write offset).
func (c *CgroupSysctlContext) FilePos() uint32 { panic(ebpfOnly("CgroupSysctlContext.FilePos")) }

// SetFilePos is eBPF side only: writes the file position (not measured).
func (c *CgroupSysctlContext) SetFilePos(v uint32) { panic(ebpfOnly("CgroupSysctlContext.SetFilePos")) }

// SetNewValue is eBPF side only: replaces the written value with s (helper bpf_sysctl_set_new_value). **s must be a string constant** (1 to 64 bytes, no trailing
// NUL is added), only at the top level of the program body (not inside a loop or a subprogram). The return value is the raw status (0; −EINVAL on a read call).
func (c *CgroupSysctlContext) SetNewValue(s string) int64 {
	panic(ebpfOnly("CgroupSysctlContext.SetNewValue"))
}
