//go:build linux

// Package kload queries live kernel capabilities for loaders and verification tools.
package kload

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/core"
)

// LiveCaps queries requirements.Capabilities through cilium/ebpf features.
// Only ErrNotSupported means absent; other errors, including insufficient privilege, remain errors.
type LiveCaps struct {
	// Nil uses /usr/lib/debug; a pointer to empty disables implicit search.
	UprobeDebugRoot *string
	// Explicit overrides are authoritative: a failed read never falls back.
	UprobeDebugPaths map[string]string
}

func have(err error) (bool, error) {
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		return false, nil
	}
	return false, err
}

func (LiveCaps) HasProgType(_ string, id int64) (bool, error) {
	return have(features.HaveProgramType(ebpf.ProgramType(id)))
}

func (LiveCaps) HasMapType(_ string, id int64) (bool, error) {
	return have(features.HaveMapType(ebpf.MapType(id)))
}

func (LiveCaps) HasHelper(_ string, progTypeID int64, _ string, helperID int64) (bool, error) {
	// cilium/ebpf v0.22.0 does not probe helpers for Extension, LSM, StructOps or Tracing
	// (features/prog.go helperProbeNotImplemented). This means Unknown, not absence;
	// actual loading must let the verifier decide.
	switch ebpf.ProgramType(progTypeID) {
	case ebpf.Extension, ebpf.LSM, ebpf.StructOps, ebpf.Tracing:
		return false, fmt.Errorf("cilium/ebpf has no helper probe for %v: %w", ebpf.ProgramType(progTypeID), requirements.ErrUnknown)
	}
	return have(features.HaveProgramHelper(ebpf.ProgramType(progTypeID), asm.BuiltinFunc(helperID)))
}

// Match tracepoint signatures and kernel fields against the target vmlinux BTF.
var (
	kernelSpecOnce sync.Once
	kernelSpec     *btf.Spec
	kernelSpecErr  error
)

func vmlinux() (*btf.Spec, error) {
	kernelSpecOnce.Do(func() { kernelSpec, kernelSpecErr = btf.LoadKernelSpec() })
	return kernelSpec, kernelSpecErr
}

func (LiveCaps) CheckTracepoint(name string, args []string) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %w", err)
	}
	return core.CheckTracepoint(spec, name, args), nil
}

// HasKernelFunc checks whether target BTF contains the attachment FUNC name.
// BTF cannot establish ftrace eligibility (notrace or inline); attach checks that.
func (LiveCaps) CheckFunc(name string) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %w", err)
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return []string{fmt.Sprintf("kernel function %s is not in the target BTF (fentry needs a BTF FUNC to attach to)", name)}, nil
		}
		return []string{fmt.Sprintf("kernel function %s: %v", name, err)}, nil
	}
	return nil, nil
}

// CheckKernelFuncSig checks the FUNC_PROTO argument count and the return integer's
// width and signedness after removing typedefs and qualifiers.
func (LiveCaps) CheckFuncSig(name string, nargs int, ret string) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %w", err)
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return []string{fmt.Sprintf("kernel function %s is not in the target BTF (fexit needs a BTF FUNC to attach to)", name)}, nil
		}
		return []string{fmt.Sprintf("kernel function %s: %v", name, err)}, nil
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return []string{fmt.Sprintf("kernel function %s has no FUNC_PROTO", name)}, nil
	}
	var diffs []string
	if len(proto.Params) != nargs {
		diffs = append(diffs, fmt.Sprintf("kernel function %s takes %d arguments in the target BTF, but the object reads its return value after %d (fexit's return slot is after the arguments)", name, len(proto.Params), nargs))
	}
	it, ok := btf.UnderlyingType(proto.Return).(*btf.Int)
	want := ret
	if !ok {
		diffs = append(diffs, fmt.Sprintf("kernel function %s does not return an integer in the target BTF (the object reads %s)", name, want))
	} else {
		got := fmt.Sprintf("u%d", it.Size*8)
		if it.Encoding&btf.Signed != 0 {
			got = fmt.Sprintf("i%d", it.Size*8)
		}
		if got != want {
			diffs = append(diffs, fmt.Sprintf("kernel function %s returns %s in the target BTF, but the object reads %s", name, got, want))
		}
	}
	return diffs, nil
}

func (LiveCaps) CheckKFields(kf []requirements.KField) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %w", err)
	}
	return core.CheckKFields(kf, spec), nil
}

// Probe a minimal requirements.BTFFeatureBlob directly with btf.NewHandleFromRawBTF.
// This bypasses marshal rewriting and is independent of KernelMarshalOptions probes.
// EINVAL means unsupported; other errors, including privilege or missing BTF, mean Unknown.
//
// Loader rewriting is inferred from an unsupported feature and the loader declaration.
// For the four features cilium can rewrite, cross-check this probe against
// KernelMarshalOptions. If unsupported and rewrites disagree, return Unknown rather
// than make an unsafe prediction from different privileges, errno or probe shapes.
func (LiveCaps) HasBTFFeature(f string) (bool, error) {
	has, err := probeBTFFeature(f)
	if err != nil {
		return false, err
	}
	if err := crossCheckCilium(f, has, CiliumRewrites()); err != nil {
		return false, err
	}
	return has, nil
}

// crossCheckCilium compares support from our probe with cilium's rewrite decision.
// For rewritable features, unsupported must equal rewrites; disagreement is Unknown.
func crossCheckCilium(f string, has bool, rewrites map[string]bool) error {
	if rw, rewritable := rewrites[f]; rewritable && rw == has {
		return fmt.Errorf("BTF feature %s: this probe says accepted=%v but cilium/ebpf's own probe says rewrite=%v — the prediction of the loader's rewrite cannot be trusted: %w", f, has, rw, requirements.ErrUnknown)
	}
	return nil
}

func probeBTFFeature(f string) (bool, error) {
	blob, err := requirements.BTFFeatureBlob(f)
	if err != nil {
		return false, err
	}
	h, err := btf.NewHandleFromRawBTF(blob)
	if err == nil {
		h.Close()
		return true, nil
	}
	if errors.Is(err, unix.EINVAL) {
		return false, nil
	}
	return false, fmt.Errorf("probe BTF %s: %w", f, err)
}

// ProbeBTFFeature returns the raw probe answer before cross-checking cilium.
func ProbeBTFFeature(f string) (bool, error) { return probeBTFFeature(f) }

// CiliumRewrites returns cilium/ebpf's actual load-time BTF rewrite flags
// from btf.KernelMarshalOptions, indexed by the four BTFRewritable feature names.
func CiliumRewrites() map[string]bool {
	o := btf.KernelMarshalOptions()
	return map[string]bool{"func_global": o.StripFuncLinkage, "decl_tag": o.ReplaceDeclTags, "type_tag": o.ReplaceTypeTags, "enum64": o.ReplaceEnum64}
}

// Loader declares the loader used with these capabilities: cilium/ebpf v0.22.
func (LiveCaps) Loader() requirements.LoaderDecl { return requirements.Cilium022 }

// Arch reports the target architecture from uname for requirements.KernelArch.
func (LiveCaps) Arch() (string, error) {
	var u unix.Utsname
	if err := unix.Uname(&u); err != nil {
		return "", fmt.Errorf("uname: %v: %w", err, requirements.ErrUnknown)
	}
	return unix.ByteSliceToString(u.Machine[:]), nil
}

// CheckStructField checks a target BTF struct member's byte offset and size.
// Unreadable target BTF means Unknown.
func (LiveCaps) CheckStructField(st, field string, offset, size int) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %v: %w", err, requirements.ErrUnknown)
	}
	var s *btf.Struct
	if err := spec.TypeByName(st, &s); err != nil {
		if errors.Is(err, btf.ErrNotFound) {
			return []string{fmt.Sprintf("struct %s is not in the target BTF", st)}, nil
		}
		return []string{fmt.Sprintf("struct %s: %v", st, err)}, nil
	}
	for _, m := range s.Members {
		if m.Name != field {
			continue
		}
		if m.BitfieldSize != 0 || m.Offset%8 != 0 {
			return []string{fmt.Sprintf("%s.%s is a bitfield in the target BTF", st, field)}, nil
		}
		sz, err := btf.Sizeof(m.Type)
		if err != nil {
			return []string{fmt.Sprintf("%s.%s: %v", st, field, err)}, nil
		}
		if int(m.Offset/8) != offset || sz != size {
			return []string{fmt.Sprintf("%s.%s is at offset %d with %d bytes in the target BTF, but the object reads offset %d with %d bytes", st, field, m.Offset/8, sz, offset, size)}, nil
		}
		return nil, nil
	}
	return []string{fmt.Sprintf("%s has no member %s in the target BTF", st, field)}, nil
}

// HasKernelSymbol searches /proc/kallsyms, including module symbols marked [mod].
// Unreadable symbols mean Unknown. Names are visible without root; addresses may
// be zero and are not inspected.
func (LiveCaps) HasKernelSymbol(name string) (bool, error) {
	b, err := os.ReadFile("/proc/kallsyms")
	if err != nil {
		return false, fmt.Errorf("kallsyms: %v: %w", err, requirements.ErrUnknown)
	}
	for _, l := range strings.Split(string(b), "\n") {
		f := strings.Fields(l)
		if len(f) >= 3 && f[2] == name {
			return true, nil
		}
	}
	return false, nil
}

// CheckFuncParam checks whether parameter n of the target BTF FUNC_PROTO is the
// integer typ after removing typedefs and qualifiers. Unreadable BTF or a missing
// FUNC means Unknown and blocks load: kprobes can attach without a BTF function.
func (LiveCaps) CheckFuncParam(name string, n int, typ string) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %v: %w", err, requirements.ErrUnknown)
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		return nil, fmt.Errorf("kernel function %s has no FUNC in the target BTF (%v): %w", name, err, requirements.ErrUnknown)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return nil, fmt.Errorf("kernel function %s has no FUNC_PROTO: %w", name, requirements.ErrUnknown)
	}
	if n > len(proto.Params) {
		return []string{fmt.Sprintf("kernel function %s takes %d arguments in the target BTF, but the object reads argument %d", name, len(proto.Params), n)}, nil
	}
	p := proto.Params[n-1]
	got := describeParam(p.Type)
	if got != typ {
		return []string{fmt.Sprintf("argument %d (%s) of kernel function %s is %s in the target BTF, but the object reads it as %s", n, requirements.ArgName(p.Name), name, got, typ)}, nil
	}
	return nil, nil
}

// CheckKernelFuncArgs checks that each FUNC_PROTO parameter points to args[i]'s
// struct; '-' skips that parameter. Missing FUNC or FUNC_PROTO means ErrUnknown
// and blocks load with farg_unknown.
func (LiveCaps) CheckFuncArgs(name string, args []string) ([]string, error) {
	spec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %v: %w", err, requirements.ErrUnknown)
	}
	var fn *btf.Func
	if err := spec.TypeByName(name, &fn); err != nil {
		return nil, fmt.Errorf("kernel function %s has no FUNC in the target BTF (%v): %w", name, err, requirements.ErrUnknown)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return nil, fmt.Errorf("kernel function %s has no FUNC_PROTO: %w", name, requirements.ErrUnknown)
	}
	if len(args) > len(proto.Params) {
		return []string{fmt.Sprintf("kernel function %s takes %d arguments in the target BTF, but the object declares %d", name, len(proto.Params), len(args))}, nil
	}
	var out []string
	for i, want := range args {
		if want == "-" {
			continue
		}
		p := proto.Params[i]
		pt, isPtr := btf.UnderlyingType(p.Type).(*btf.Pointer)
		if !isPtr {
			out = append(out, fmt.Sprintf("argument %d (%s) of kernel function %s is %s in the target BTF, not a pointer to struct %s", i, requirements.ArgName(p.Name), name, describeParam(p.Type), want))
			continue
		}
		st, isStruct := btf.UnderlyingType(pt.Target).(*btf.Struct)
		if !isStruct || st.Name != want {
			out = append(out, fmt.Sprintf("argument %d (%s) of kernel function %s points to %s in the target BTF, not struct %s", i, requirements.ArgName(p.Name), name, pt.Target, want))
		}
	}
	return out, nil
}

// describeParam spells integers as i32, u64, etc., pointers as ptr, and other types by BTF kind.
func describeParam(t btf.Type) string {
	switch u := btf.UnderlyingType(t).(type) {
	case *btf.Int:
		if u.Encoding&btf.Signed != 0 {
			return fmt.Sprintf("i%d", u.Size*8)
		}
		return fmt.Sprintf("u%d", u.Size*8)
	case *btf.Pointer:
		return "ptr"
	case *btf.Enum:
		return fmt.Sprintf("enum%d", u.Size*8)
	default:
		return fmt.Sprintf("%T", u)
	}
}

// HasTCX attempts link creation with a nonexistent ifindex, like cilium's haveTCX.
// ENODEV establishes support. EPERM or EACCES from sched_cls loading or link
// creation means Unknown, not absence.
func (LiveCaps) HasTCX() (bool, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Type:         ebpf.SchedCLS,
		License:      "GPL",
		Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
	})
	if err != nil {
		// Neither insufficient privilege nor absent sched_cls establishes TCX support.
		return false, fmt.Errorf("load a sched_cls probe: %v: %w", err, requirements.ErrUnknown)
	}
	defer prog.Close()
	// union bpf_attr link_create: prog_fd, target_ifindex, attach_type, flags (u32 each); remainder zero.
	var attr [64]byte
	binary.LittleEndian.PutUint32(attr[0:], uint32(prog.FD()))
	binary.LittleEndian.PutUint32(attr[4:], ^uint32(0))
	binary.LittleEndian.PutUint32(attr[8:], uint32(ebpf.AttachTCXIngress))
	_, _, errno := unix.Syscall(unix.SYS_BPF, 28 /* BPF_LINK_CREATE */, uintptr(unsafe.Pointer(&attr[0])), uintptr(len(attr)))
	switch errno {
	case unix.ENODEV:
		return true, nil
	case unix.EINVAL:
		return false, nil
	case unix.EPERM, unix.EACCES:
		return false, fmt.Errorf("create a tcx link: %v: %w", errno, requirements.ErrUnknown)
	case 0:
		return false, fmt.Errorf("create a tcx link on ifindex ^0 succeeded unexpectedly: %w", requirements.ErrUnknown)
	}
	return false, fmt.Errorf("create a tcx link: %v: %w", errno, requirements.ErrUnknown)
}
