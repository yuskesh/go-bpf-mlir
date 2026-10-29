package bpf

import (
	"fmt"
	"reflect"

	"github.com/yuskesh/go-bpf-mlir/bindrt"

	"github.com/yuskesh/go-bpf-mlir/internal/binding"
)

// User-space stacks (bpf-mlir's ebpf.stack.user_id).
//
//	var Stacks = bpf.StackTrace{MaxEntries: 256, Depth: 32}   // an IP stack (u64 × Depth)
//	var Builds = bpf.StackBuildID{MaxEntries: 256, Depth: 32} // a build id stack (32 bytes × Depth, flags BPF_F_STACK_BUILD_ID)
//	st := Stacks.UserID(ctx, 0)  // uprobe, kprobe, fentry programs — an id (≥ 0) or a negative errno
//
// **Signs of a target without frame pointers**: on x86_64 the user stack walk uses only frame pointers (the rbp chain) — a target without frame pointers
// (the gcc / clang -O2 default) still succeeds with id ≥ 0 (invisible to compile and to the load check), and after the first frame (the probed location) it **ends at depth 1, or
// has fake frames read from caller values that use rbp as a general-purpose register** (the latter on all three kernels: addresses outside executable mappings
// follow, and they can even show status 1 in a build id stack). Rebuild the target with `-fno-omit-frame-pointer`.
// Go binaries have frame pointers. The depth is the number of elements from StackTrace.Get (StackDepth).

// StackContext is the marker of program contexts that can take the user stack (*FentryContext, *KprobeContext, *UprobeContext).
type StackContext interface{ gobpfStackContext() }

func (*FentryContext) gobpfStackContext() {}
func (*KprobeContext) gobpfStackContext() {}
func (*UprobeContext) gobpfStackContext() {}

// UserID is eBPF side only (only in uprobe, kprobe and fentry program bodies): records the current task's user-space stack, excluding the first skip frames,
// and returns **the raw status** (an id ≥ 0 or a negative errno — a bucket collision gives −EEXIST). skip is a constant 0 to 255. A statement that discards the status is GB017; not inside a loop.
// For signs of a target without frame pointers, see the type doc.
func (m *StackTrace) UserID(ctx StackContext, skip uint32) int64 {
	panic(ebpfOnly("StackTrace.UserID"))
}

// UserIDReuse is the same as UserID, but overwrites the previous stack on a bucket collision (BPF_F_REUSE_STACKID — −ENOMEM if there is no free element).
func (m *StackTrace) UserIDReuse(ctx StackContext, skip uint32) int64 {
	panic(ebpfOnly("StackTrace.UserIDReuse"))
}

// StackDepth is the depth of an IP stack (the number of elements before the first 0 — bindrt.StackDepth). A user stack of depth 1 is a sign of a target without frame pointers.
func StackDepth(ips []uint64) int { return bindrt.StackDepth(ips) }

// StackBuildID is the declaration of a build id stack map (BPF_MAP_TYPE_STACK_TRACE + BPF_F_STACK_BUILD_ID): the key is an id (u32), and the value is Depth
// 32-byte elements `struct bpf_stack_build_id { s32 status; u8 build_id[20]; union { u64 offset; u64 ip; } }`. Only UserID / UserIDReuse
// (there is no build id for the kernel stack — bpf-mlir rejects it).
//
// **Per-element status** (StackFrame.Status): 1 valid (build id and file offset), 2 ip (the build id could not be taken and it fell back to the IP — no mapping, no build id
// note or an unreadable one, the page not in memory, etc.; the kernel makes it an IP **silently**), 0 empty (the end of the stack). ip elements are not dropped or rounded.
// status 1 only says "the file mapping containing the address had a build id", not that the frame is a real return address (a fake frame of a target without frame pointers
// landed in ld.so's data mapping and got status 1). Frames of binaries from Go's internal linker have status 2 — the GNU
// build id note exists but outside the PT_NOTE segment, and the kernel looks only at PT_NOTE.
type StackBuildID struct {
	// MaxEntries is the number of stack buckets (a positive constant).
	MaxEntries uint32
	// Depth is the maximum number of elements in one stack (a nonzero constant — each element is 32 bytes).
	Depth uint32
}

// StackBuildIDEntry is the bytes of one element of a build id stack (32 bytes — the schema's stack_build_id, used to check gobpf's map declaration).
type StackBuildIDEntry [bindrt.StackBuildIDEntrySize]byte

// StackFrame is one element of a build id stack (bindrt.StackBuildIDFrame — read by the rules of bindrt.DecodeStackBuildID as is).
type StackFrame = bindrt.StackBuildIDFrame

// StackFrameStatus is the type of StackFrame.Status (bindrt.StackFrameStatus — the values are the UAPI enum bpf_stack_build_id_status; an alias).
type StackFrameStatus = bindrt.StackFrameStatus

// Per-element status values (the same as the bindrt constants).
const (
	StackFrameEmpty = bindrt.StackFrameEmpty // 0 — the end of the stack
	StackFrameValid = bindrt.StackFrameValid // 1 — build id and file offset
	StackFrameIP    = bindrt.StackFrameIP    // 2 — the build id could not be taken; fell back to the IP
)

// UserID is the same as StackTrace.UserID (build id stack).
func (m *StackBuildID) UserID(ctx StackContext, skip uint32) int64 {
	panic(ebpfOnly("StackBuildID.UserID"))
}

// UserIDReuse is the same as StackTrace.UserIDReuse (build id stack).
func (m *StackBuildID) UserIDReuse(ctx StackContext, skip uint32) int64 {
	panic(ebpfOnly("StackBuildID.UserIDReuse"))
}

// Get is user space only: the elements of stack id (bindrt.DecodeStackBuildID — stops at the first empty element, per-element status as is). A missing id is an error.
func (m *StackBuildID) Get(id uint32) ([]StackFrame, error) {
	mp, err := binding.Map(m, "StackBuildID.Get")
	if err != nil {
		return nil, err
	}
	buf := make([]byte, mp.ValueSize())
	if err := mp.Lookup(id, buf); err != nil {
		return nil, fmt.Errorf("StackBuildID.Get: map %s id %d: %w", binding.Symbol(m), id, err)
	}
	return bindrt.DecodeStackBuildID(buf)
}

// Delete is user space only: deletes stack id (frees the bucket). The delete-after-read shape and its caveats are the same as StackTrace.Delete.
func (m *StackBuildID) Delete(id uint32) error { return mapRemove(m, "StackBuildID.Delete", id) }

// GobpfTypes is an internal API of the gobpf runtime — the key is a u32 and the value is [Depth]StackBuildIDEntry.
func (m *StackBuildID) GobpfTypes() (key, value reflect.Type) {
	return reflect.TypeFor[uint32](), reflect.ArrayOf(int(m.Depth), reflect.TypeFor[StackBuildIDEntry]())
}

// GobpfMapKind is an internal API of the gobpf runtime (the same as Array.GobpfMapKind).
func (m *StackBuildID) GobpfMapKind() string { return "stack_trace" }

// GobpfMapFlags is an internal API of the gobpf runtime: BPF_F_STACK_BUILD_ID (32 — the flags of a build id stack map).
func (m *StackBuildID) GobpfMapFlags() uint64 { return 32 }
