//go:build linux

package kload

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/core"
)

// BTF-file query only: no program load, attach or writable_size probe.
func (LiveCaps) CheckTracepointBuffer(name, pointee string) ([]string, error) {
	spec, err := vmlinux()
	return checkTracepointBufferSpec(spec, err, name, pointee)
}

func checkTracepointBufferSpec(spec *btf.Spec, err error, name, pointee string) ([]string, error) {
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
			return nil, fmt.Errorf("tracepoint %s BTF unavailable: %w: %w", name, err, requirements.ErrUnknown)
		}
		return nil, fmt.Errorf("tracepoint %s target BTF: %w", name, err)
	}
	return core.CheckTracepointBuffer(spec, name, pointee)
}
