//go:build linux

package kload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"golang.org/x/sys/unix"
)

// Dependencies are passed to the probe, never installed as a process-wide fake.
type netkitProbeOps struct {
	load  func(ebpf.AttachType) (int, func() error, error)
	link  func(int, ebpf.AttachType) (int, error)
	close func(int) error
}

// HasNetkit probes the link hook without attaching to a real network device.
func (LiveCaps) HasNetkit(direction string) (bool, error) {
	return probeNetkit(direction, netkitProbeOps{
		load: func(at ebpf.AttachType) (int, func() error, error) {
			p, err := ebpf.NewProgram(&ebpf.ProgramSpec{
				Type: ebpf.SchedCLS, AttachType: at, License: "GPL",
				Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
			})
			if err != nil {
				return -1, nil, err
			}
			return p.FD(), p.Close, nil
		},
		link: func(fd int, at ebpf.AttachType) (int, error) {
			attr := netkitLinkAttr(fd, at)
			linkFD, _, errno := unix.Syscall(unix.SYS_BPF, 28 /* BPF_LINK_CREATE */, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
			if errno != 0 {
				return -1, errno
			}
			return int(linkFD), nil
		},
		close: unix.Close,
	})
}

func netkitLinkAttr(fd int, at ebpf.AttachType) [64]byte {
	var attr [64]byte
	binary.LittleEndian.PutUint32(attr[0:], uint32(fd))
	binary.LittleEndian.PutUint32(attr[4:], ^uint32(0)) // No existing interface can have this ifindex.
	binary.LittleEndian.PutUint32(attr[8:], uint32(at))
	return attr // flags, revision and anchor are zero.
}

func probeNetkit(direction string, ops netkitProbeOps) (have bool, result error) {
	var at ebpf.AttachType
	switch direction {
	case "primary":
		at = ebpf.AttachNetkitPrimary
	case "peer":
		at = ebpf.AttachNetkitPeer
	default:
		return false, fmt.Errorf("netkit: unknown direction %q", direction)
	}
	fd, closeProgram, err := ops.load(at)
	if err != nil {
		return false, fmt.Errorf("load a netkit %s probe: %w: %w", direction, err, requirements.ErrUnknown)
	}
	defer func() {
		if err := closeProgram(); err != nil {
			have = false
			result = errors.Join(result, fmt.Errorf("close netkit probe program: %w: %w", err, requirements.ErrUnknown))
		}
	}()
	linkFD, err := ops.link(fd, at)
	switch {
	case errors.Is(err, unix.ENODEV):
		return true, nil
	case errors.Is(err, unix.EINVAL):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("create a netkit %s link: %w: %w", direction, err, requirements.ErrUnknown)
	default:
		result = fmt.Errorf("create a netkit %s link on ifindex ^0 succeeded unexpectedly: %w", direction, requirements.ErrUnknown)
		if err := ops.close(linkFD); err != nil {
			result = errors.Join(result, fmt.Errorf("close unexpected netkit link: %w", err))
		}
		return false, result
	}
}
