//go:build linux

package kload

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/btfexact"
)

// EnumValue answers enum_values from the target vmlinux BTF: the 64-bit
// pattern of constant name in the ENUM / ENUM64 named enum. cilium sign-extends
// signed 32-bit ENUM values, as ebpf-abigen does for the UAPI table. BTF-file
// query only: no program load.
func (LiveCaps) EnumValue(enum, name string) (uint64, error) {
	spec, err := vmlinux()
	return enumValueSpec(spec, err, enum, name)
}

func enumValueSpec(spec *btf.Spec, err error, enum, name string) (uint64, error) {
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
			return 0, fmt.Errorf("enum %s BTF unavailable: %w: %w", enum, err, requirements.ErrUnknown)
		}
		return 0, fmt.Errorf("enum %s target BTF: %w", enum, err)
	}
	var e *btf.Enum
	if err := btfexact.TypeByName(spec, enum, &e); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return 0, fmt.Errorf("target BTF has no enum %s: %w", enum, requirements.ErrEnumAbsent)
		}
		return 0, fmt.Errorf("enum %s target BTF: %w", enum, err)
	}
	for _, v := range e.Values {
		if v.Name == name {
			return v.Value, nil
		}
	}
	return 0, fmt.Errorf("target BTF enum %s has no %s: %w", enum, name, requirements.ErrEnumAbsent)
}
