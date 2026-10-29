package bindrt

import (
	"encoding/binary"
	"fmt"
)

// Build-ID stack values contain D entries of struct bpf_stack_build_id:
// s32 status, u8 build_id[20], then u64 offset or ip (32 bytes total). Preserve
// each status: missing VMA/notes/cached pages, mmap-lock failures and kernel
// stacks can silently fall back to IP. The kernel reads notes only in PT_NOTE;
// Go internal-linker binaries can place .note.gnu.build-id outside that segment.
// User stacks require frame pointers. Without them, unwinding may stop at depth
// one or yield false frames, even status-valid frames in file mappings. Check
// depth and executable mappings; status valid alone does not prove a real frame.
//
// StackFrameStatus follows UAPI enum bpf_stack_build_id_status. The stdlib-only
// constants are checked by TestStackFrameStatusMatchesUAPITable in a developer
// checkout against abi/uapi.tsv stackbidstatus.
type StackFrameStatus int32

const (
	// StackFrameEmpty is an unused entry and terminates the stack.
	StackFrameEmpty StackFrameStatus = 0
	// StackFrameValid contains a build ID and a file offset within its object.
	StackFrameValid StackFrameStatus = 1
	// StackFrameIP preserves the kernel's fallback IP when no build ID is available.
	StackFrameIP StackFrameStatus = 2
)

func (s StackFrameStatus) String() string {
	switch s {
	case StackFrameEmpty:
		return "empty"
	case StackFrameValid:
		return "valid"
	case StackFrameIP:
		return "ip"
	}
	return fmt.Sprintf("status(%d)", int32(s))
}

// StackBuildIDEntrySize is the UAPI sizeof(struct bpf_stack_build_id).
const StackBuildIDEntrySize = 32

// StackBuildIDFrame uses BuildID/Offset for StackFrameValid and IP for StackFrameIP.
type StackBuildIDFrame struct {
	Status  StackFrameStatus
	BuildID [20]byte
	Offset  uint64 // File offset within the build-ID object when Status == StackFrameValid.
	IP      uint64 // Virtual address when Status == StackFrameIP.
}

// DecodeStackBuildID reads D*32-byte values, stopping at the first empty entry.
// It rejects nonmultiples of 32 and reports unknown statuses by entry index.
func DecodeStackBuildID(b []byte) ([]StackBuildIDFrame, error) {
	if len(b)%StackBuildIDEntrySize != 0 {
		return nil, fmt.Errorf("a build id stack value is %d bytes, not a multiple of %d (struct bpf_stack_build_id)", len(b), StackBuildIDEntrySize)
	}
	var out []StackBuildIDFrame
	for i := 0; i < len(b)/StackBuildIDEntrySize; i++ {
		e := b[i*StackBuildIDEntrySize : (i+1)*StackBuildIDEntrySize]
		var f StackBuildIDFrame
		f.Status = StackFrameStatus(int32(binary.LittleEndian.Uint32(e[0:4])))
		copy(f.BuildID[:], e[4:24])
		v := binary.LittleEndian.Uint64(e[24:32])
		switch f.Status {
		case StackFrameEmpty:
			return out, nil
		case StackFrameValid:
			f.Offset = v
		case StackFrameIP:
			f.IP = v
		default:
			return out, fmt.Errorf("build id stack entry %d has an unknown status %d (want 0 empty, 1 valid or 2 ip)", i, int32(f.Status))
		}
		out = append(out, f)
	}
	return out, nil
}

// StackDepth counts entries before the first zero IP. Depth one may indicate
// missing frame pointers, but deeper stacks can also contain false frames;
// callers should inspect frame mappings.
func StackDepth(ips []uint64) int {
	for i, ip := range ips {
		if ip == 0 {
			return i
		}
	}
	return len(ips)
}

// DecodeStackIPs reads little-endian u64 IPs up to the first zero.
func DecodeStackIPs(b []byte) ([]uint64, error) {
	if len(b)%8 != 0 {
		return nil, fmt.Errorf("a stack value is %d bytes, not a multiple of 8 (u64 IPs)", len(b))
	}
	ips := make([]uint64, len(b)/8)
	for i := range ips {
		ips[i] = binary.LittleEndian.Uint64(b[i*8:])
	}
	return ips[:StackDepth(ips)], nil
}
