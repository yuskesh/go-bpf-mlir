//go:build linux

package kload

// Raw loading supplies attach BTF IDs missing from cilium v0.22's handling of
// lsm_cgroup/fsession. Its findProgramTargetInKernel ignores unrecognized
// attach types and loads with attach_btf_id zero, which the kernel rejects.
// ProgramSpec has no field for supplying that ID, so probes and developer
// runners call BPF_PROG_LOAD directly. Compiler/requirements semantics and
// cilium's loader declaration remain unchanged.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"
)

// AttachTraceFsession is UAPI BPF_TRACE_FSESSION=58, absent from cilium v0.22's
// public ebpf constants though present in its internal sys package.
const AttachTraceFsession = ebpf.AttachType(58)

// IsLSMCgroup recognizes LSM programs with expected attach BPF_LSM_CGROUP.
func IsLSMCgroup(spec *ebpf.ProgramSpec) bool {
	return spec != nil && spec.Type == ebpf.LSM && spec.AttachType == ebpf.AttachLSMCgroup
}

// IsFsession recognizes TRACING programs with expected attach BPF_TRACE_FSESSION.
func IsFsession(spec *ebpf.ProgramSpec) bool {
	return spec != nil && spec.Type == ebpf.Tracing && spec.AttachType == AttachTraceFsession
}

// NeedsRawLoad identifies program kinds whose attach BTF ID cilium cannot resolve.
func NeedsRawLoad(spec *ebpf.ProgramSpec) bool { return IsLSMCgroup(spec) || IsFsession(spec) }

// LSMCgroupLoadError retains raw-load errno and verifier log, also for fsession.
type LSMCgroupLoadError struct {
	Errno unix.Errno
	Log   string
}

func (e *LSMCgroupLoadError) Error() string {
	return fmt.Sprintf("load program (raw BTF attach): %v: %s", e.Errno, e.Log)
}

func (e *LSMCgroupLoadError) Unwrap() error { return e.Errno }

const bpfProgLoad = 5 // UAPI BPF_PROG_LOAD.

// LoadLSMCgroup raw-loads lsm_cgroup programs without kfunc calls.
func LoadLSMCgroup(spec *ebpf.ProgramSpec, maps map[string]*ebpf.Map) (*ebpf.Program, error) {
	if !IsLSMCgroup(spec) {
		return nil, fmt.Errorf("program %s is not an lsm_cgroup program (%s/%s)", spec.Name, spec.Type, spec.AttachType)
	}
	return LoadRaw(spec, maps, "")
}

// LoadFsession uses elfPath relocations to resolve kfunc call names. elfPath
// may be empty only for programs without kfunc calls.
func LoadFsession(spec *ebpf.ProgramSpec, maps map[string]*ebpf.Map, elfPath string) (*ebpf.Program, error) {
	if !IsFsession(spec) {
		return nil, fmt.Errorf("program %s is not an fsession program (%s/%s)", spec.Name, spec.Type, spec.AttachType)
	}
	return LoadRaw(spec, maps, elfPath)
}

// LoadRaw rewrites map references to supplied ELF-symbol map FDs and kfunc
// calls to vmlinux FUNC IDs using ELF relocations (module kfuncs unsupported).
// Resolve attach_btf_id from bpf_lsm_<AttachTo> for lsm_cgroup or <AttachTo>
// for fsession, then BPF_PROG_LOAD. Refuse bpf-to-bpf calls/function references.
// Kernel rejections return LSMCgroupLoadError with a log.
func LoadRaw(spec *ebpf.ProgramSpec, maps map[string]*ebpf.Map, elfPath string) (*ebpf.Program, error) {
	return loadRaw(spec, maps, elfPath, false)
}

// LoadRawWithBTF also supplies func_info/line_info and prog_btf_fd using
// cilium MarshalExtInfos, enabling checks of loaded program BTF identity.
// Refuse CO-RE relocations: raw loading does not apply them. LoadRaw behavior
// remains unchanged.
func LoadRawWithBTF(spec *ebpf.ProgramSpec, maps map[string]*ebpf.Map, elfPath string) (*ebpf.Program, error) {
	return loadRaw(spec, maps, elfPath, true)
}

func loadRaw(spec *ebpf.ProgramSpec, maps map[string]*ebpf.Map, elfPath string, withBTF bool) (*ebpf.Program, error) {
	if !NeedsRawLoad(spec) {
		return nil, fmt.Errorf("program %s (%s/%s) does not need the raw load", spec.Name, spec.Type, spec.AttachType)
	}
	if spec.AttachTo == "" {
		return nil, fmt.Errorf("program %s: the raw load needs the attach target (AttachTo)", spec.Name)
	}
	kspec, err := vmlinux()
	if err != nil {
		return nil, fmt.Errorf("target BTF: %w", err)
	}
	funcID := func(name string) (btf.TypeID, error) {
		var fn *btf.Func
		if err := kspec.TypeByName(name, &fn); err != nil {
			return 0, err
		}
		return kspec.TypeID(fn)
	}
	target := spec.AttachTo
	if IsLSMCgroup(spec) {
		target = "bpf_lsm_" + spec.AttachTo
	}
	btfID, err := funcID(target)
	if err != nil {
		return nil, fmt.Errorf("attach target %s: %w", target, err)
	}
	var kfuncAt map[int]string // Raw instruction byte offset to ELF-relocated kfunc name.
	insns := spec.Copy().Instructions
	off := 0
	for i := range insns {
		ins := &insns[i]
		switch {
		case ins.IsLoadFromMap():
			name := ins.Reference()
			m := maps[name]
			if m == nil {
				return nil, fmt.Errorf("program %s: map %q is not loaded", spec.Name, name)
			}
			if err := ins.AssociateMap(m); err != nil {
				return nil, fmt.Errorf("program %s: map %q: %w", spec.Name, name, err)
			}
		case ins.IsKfuncCall():
			if kfuncAt == nil {
				if elfPath == "" {
					return nil, fmt.Errorf("program %s: instruction %d is a kfunc call and no ELF was given to name it", spec.Name, i)
				}
				if kfuncAt, err = kfuncRelocs(elfPath, spec.SectionName); err != nil {
					return nil, fmt.Errorf("program %s: %w", spec.Name, err)
				}
			}
			name, ok := kfuncAt[off]
			if !ok {
				return nil, fmt.Errorf("program %s: kfunc call at byte %d has no relocation in section %s", spec.Name, off, spec.SectionName)
			}
			id, err := funcID(name)
			if err != nil {
				return nil, fmt.Errorf("program %s: kfunc %s: %w", spec.Name, name, err)
			}
			ins.Constant = int64(id)
			ins.Offset = 0 // vmlinux at fd_array index zero.
		case ins.IsFunctionCall(), ins.IsFunctionReference():
			return nil, fmt.Errorf("program %s: instruction %d is a call / reference the raw load does not link", spec.Name, i)
		}
		off += int(ins.Size())
	}
	// Collect instruction func_info/line_info types in one program BTF handle.
	var fib, lib []byte
	var progBTF *btf.Handle
	if withBTF {
		var b *btf.Builder
		if fib, lib, b, err = rawExtInfos(spec.Name, insns); err != nil {
			return nil, err
		}
		if !b.Empty() {
			if progBTF, err = btf.NewHandle(b); err != nil {
				return nil, fmt.Errorf("program %s: load BTF: %w", spec.Name, err)
			}
			defer progBTF.Close()
		}
	}
	var buf bytes.Buffer
	if err := insns.Marshal(&buf, binary.LittleEndian); err != nil {
		return nil, fmt.Errorf("program %s: %w", spec.Name, err)
	}
	code := buf.Bytes()
	license := append([]byte(spec.License), 0)
	if spec.License == "" {
		license = []byte("GPL\x00")
	}
	load := func(logBuf []byte) (int, unix.Errno) {
		var attr [128]byte
		le := binary.LittleEndian
		le.PutUint32(attr[0:], uint32(spec.Type))
		le.PutUint32(attr[4:], uint32(len(code)/8))
		le.PutUint64(attr[8:], uint64(uintptr(unsafe.Pointer(&code[0]))))
		le.PutUint64(attr[16:], uint64(uintptr(unsafe.Pointer(&license[0]))))
		if len(logBuf) > 0 {
			le.PutUint32(attr[24:], 1) // log_level
			le.PutUint32(attr[28:], uint32(len(logBuf)))
			le.PutUint64(attr[32:], uint64(uintptr(unsafe.Pointer(&logBuf[0]))))
		}
		le.PutUint32(attr[44:], spec.Flags) // prog_flags
		name := spec.Name
		if len(name) > 15 {
			name = name[:15]
		}
		copy(attr[48:64], name)
		le.PutUint32(attr[68:], uint32(spec.AttachType)) // expected_attach_type
		if progBTF != nil { // Attribute offsets: prog_btf_fd@72, func_info_rec_size@76, func_info@80,
	// func_info_cnt@88, line_info_rec_size@92, line_info@96, line_info_cnt@104.
			le.PutUint32(attr[72:], uint32(progBTF.FD()))
			if len(fib) > 0 {
				le.PutUint32(attr[76:], btf.FuncInfoSize)
				le.PutUint64(attr[80:], uint64(uintptr(unsafe.Pointer(&fib[0]))))
				le.PutUint32(attr[88:], uint32(len(fib))/btf.FuncInfoSize)
			}
			if len(lib) > 0 {
				le.PutUint32(attr[92:], btf.LineInfoSize)
				le.PutUint64(attr[96:], uint64(uintptr(unsafe.Pointer(&lib[0]))))
				le.PutUint32(attr[104:], uint32(len(lib))/btf.LineInfoSize)
			}
		}
		le.PutUint32(attr[108:], uint32(btfID)) // attach_btf_id (vmlinux — attach_btf_obj_fd 0)
		fd, _, errno := unix.Syscall(unix.SYS_BPF, bpfProgLoad, uintptr(unsafe.Pointer(&attr[0])), unsafe.Sizeof(attr))
		runtime.KeepAlive(fib)
		runtime.KeepAlive(lib)
		runtime.KeepAlive(code)
		runtime.KeepAlive(license)
		runtime.KeepAlive(logBuf)
		return int(fd), errno
	}
	fd, errno := load(nil)
	if errno != 0 {
		logBuf := make([]byte, 1<<20)
		fd2, errno2 := load(logBuf)
		if errno2 == 0 {
			unix.Close(fd2)
			return nil, fmt.Errorf("program %s: the load failed (%v) and then succeeded with a log", spec.Name, errno)
		}
		return nil, &LSMCgroupLoadError{Errno: errno, Log: string(bytes.TrimRight(logBuf, "\x00"))}
	}
	p, err := ebpf.NewProgramFromFD(fd)
	if err != nil {
		unix.Close(fd)
		return nil, err
	}
	return p, nil
}

// rawExtInfos builds function/line metadata and its BTF, rejecting CO-RE
// relocations in instructions.
func rawExtInfos(name string, insns asm.Instructions) (fib, lib []byte, b *btf.Builder, err error) {
	for i := range insns {
		if btf.CORERelocationMetadata(&insns[i]) != nil {
			return nil, nil, nil, fmt.Errorf("program %s: instruction %d has a CO-RE relocation the raw load does not apply", name, i)
		}
	}
	b = new(btf.Builder)
	if fib, lib, err = btf.MarshalExtInfos(insns, b); err != nil {
		return nil, nil, nil, fmt.Errorf("program %s: marshal ext_infos: %w", name, err)
	}
	return fib, lib, b, nil
}

// kfuncRelocs maps section byte offsets to undefined-symbol call relocations
// (.rel<section>, R_BPF_64_32). The supported input is one function beginning
// at section offset zero; additional functions in the section are out of scope.
func kfuncRelocs(path, section string) (map[int]string, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	syms, err := f.Symbols()
	if err != nil {
		return nil, err
	}
	rel := f.Section(".rel" + section)
	if rel == nil {
		return nil, fmt.Errorf("%s: no relocation section .rel%s", path, section)
	}
	data, err := rel.Data()
	if err != nil {
		return nil, err
	}
	out := map[int]string{}
	for i := 0; i+16 <= len(data); i += 16 {
		roff := binary.LittleEndian.Uint64(data[i:])
		info := binary.LittleEndian.Uint64(data[i+8:])
		symIdx := int(info >> 32)
		if symIdx < 1 || symIdx > len(syms) {
			return nil, fmt.Errorf("%s: relocation symbol %d out of range", path, symIdx)
		}
		s := syms[symIdx-1]
		if s.Section == elf.SHN_UNDEF && elf.ST_TYPE(s.Info) == elf.STT_NOTYPE && uint32(info) == 10 { // R_BPF_64_32
			out[int(roff)] = s.Name
		}
	}
	return out, nil
}

// IsLSMCgroupLoadError recognizes kernel rejection of a raw load.
func IsLSMCgroupLoadError(err error) (*LSMCgroupLoadError, bool) {
	var e *LSMCgroupLoadError
	ok := errors.As(err, &e)
	return e, ok
}
