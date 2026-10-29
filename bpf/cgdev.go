package bpf

// cgroup_device programs (bpf-mlir's cgroup_device kind):
//
//	func onDev(ctx *bpf.CgroupDeviceContext) bpf.CgroupAction {
//		if ctx.Major() == 1 && ctx.Minor() == 3 {
//			return bpf.CgroupDeny // opening /dev/null gets EPERM
//		}
//		return bpf.CgroupAllow
//	}
//
// There is no directive (the type decides the kind). Attach with gobpf.AttachCgroup — **it runs only when a task in the attached cgroup (or a child cgroup) opens a
// block / char device** (the kernel runs only the cgroup v2 programs of the opening task's cgroup). CgroupDeny makes the open (and mknod) fail with EPERM.
// A non-root loader needs CAP_BPF + CAP_NET_ADMIN.

// CgroupDeviceContext is the context of a cgroup_device program (struct bpf_cgroup_dev_ctx, read only).
type CgroupDeviceContext struct{ _ [0]func() }

// AccessType is eBPF side only: `(access << 16) | type` — access is a combination of DEVCG_ACC_MKNOD 1, READ 2 and WRITE 4; type is block 1 or char 2.
func (c *CgroupDeviceContext) AccessType() uint32 { panic(ebpfOnly("CgroupDeviceContext.AccessType")) }

// Major is eBPF side only: the device's major number.
func (c *CgroupDeviceContext) Major() uint32 { panic(ebpfOnly("CgroupDeviceContext.Major")) }

// Minor is eBPF side only: the device's minor number.
func (c *CgroupDeviceContext) Minor() uint32 { panic(ebpfOnly("CgroupDeviceContext.Minor")) }
