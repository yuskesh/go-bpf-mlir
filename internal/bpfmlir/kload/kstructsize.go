//go:build linux

package kload

import (
	"errors"
	"fmt"
	"math"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// StructSize answers kstruct_size from the target BTF: the byte size of
// the single vmlinux STRUCT name. Absent from vmlinux and every module BTF is
// ErrKStructAbsent; vmlinux unreadable, an incomplete module set, a module-only
// struct or two vmlinux structs of the name are Unknown (vmStruct — the
// btf_presence rules). BTF-file query only: no program load.
func (LiveCaps) StructSize(name string) (uint32, error) {
	s := liveSources()
	return structSizeIn(s.vm, s.vmErr, s.mods, s.modErr, name)
}

func structSizeIn(vm *btf.Spec, vmErr error, mods map[string]*btf.Spec, modErr error, name string) (uint32, error) {
	st, err := vmStruct(vm, vmErr, mods, modErr, name)
	if errors.Is(err, errTypeAbsent) {
		// Keep vmStruct's text (vmlinux and module count), swap the sentinel.
		return 0, fmt.Errorf("%s: %w", strings.TrimSuffix(err.Error(), ": "+errTypeAbsent.Error()), requirements.ErrKStructAbsent)
	}
	if err != nil {
		return 0, err
	}
	if uint64(st.Size) > math.MaxUint32 {
		return 0, fmt.Errorf("struct %s: size %d exceeds u32", name, st.Size)
	}
	return uint32(st.Size), nil
}
