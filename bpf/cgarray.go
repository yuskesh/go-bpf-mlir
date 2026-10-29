package bpf

import "reflect"

// CgroupArray is the declaration of a BPF_MAP_TYPE_CGROUP_ARRAY (bpf-mlir's cgroup_array map): the key is a u32 in 0..MaxEntries−1, and the value is a cgroup (v2)
// directory (the fd from Set). The eBPF side has only TaskUnder (whether the current task is under the slot's cgroup) and SkbUnder (whether the skb's socket's cgroup is under it).
//
//	var CG = bpf.CgroupArray{MaxEntries: 4}
//	st := CG.TaskUnder(0)       // a tracing program such as fentry — 1 is under, 0 is outside, −EAGAIN is an empty slot, −E2BIG is out of range
//	st := CG.SkbUnder(ctx, 0)   // the body context of a tc (sched_cls) program — −ENOENT if the skb has no full socket
type CgroupArray struct {
	// MaxEntries is the maximum number of slots (a nonzero constant).
	MaxEntries uint32
}

// TCContext is the context of a tc (sched_cls) program (TCIngressContext, TCEgressContext — the ctx that SkbUnder accepts).
type TCContext interface{ isTCContext() }

func (*TCIngressContext) isTCContext() {}
func (*TCEgressContext) isTCContext()  {}

// TaskUnder is eBPF side only: whether the current task is in slot k's cgroup (including its descendants) (the raw status of helper bpf_current_task_under_cgroup).
// On 6.x kernels only programs of a tracing kind (fentry, etc.) can call it (7.1.8 allows other kinds too).
func (m *CgroupArray) TaskUnder(k uint32) int64 { panic(ebpfOnly("CgroupArray.TaskUnder")) }

// SkbUnder is eBPF side only: whether the cgroup of the skb's socket is in slot k's cgroup (including its descendants) (the raw status of helper bpf_skb_under_cgroup).
// Only with the body context of a tc program.
func (m *CgroupArray) SkbUnder(ctx TCContext, k uint32) int64 {
	panic(ebpfOnly("CgroupArray.SkbUnder"))
}

// Set is user space only: puts the fd of a cgroup directory in slot k (an fd from opening a cgroup v2 directory with O_RDONLY).
func (m *CgroupArray) Set(k uint32, dirFD int) error {
	return mapPut(m, "CgroupArray.Set", k, uint32(dirFD))
}

// Clear is user space only: empties slot k.
func (m *CgroupArray) Clear(k uint32) error {
	return mapRemove(m, "CgroupArray.Clear", k)
}

// GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is a u32 (a cgroup fd).
func (m *CgroupArray) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.TypeFor[uint32]()
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *CgroupArray) GobpfMapKind() string { return "cgroup_array" }
