//go:build linux

package kload

// The strict load-only kfunc_loads recipe for bpf_arena_alloc_pages and
// bpf_arena_free_pages. It follows the C loader's arena recipe (bml f9c1cdd, src/caps/live_arena.c)
// step for step and text for text, so that ebpf-precheck and bml-precheck
// record the same answer (bml's live differential compares the caps files byte
// for byte). It creates one arena map with a raw BPF_MAP_CREATE (never mmapped)
// and loads one sleepable syscall program. No attach, no test run.

import (
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/btfexact"
)

const (
	arenaAllocPages = "bpf_arena_alloc_pages"
	arenaFreePages  = "bpf_arena_free_pages"
	// The probe map: one page, BPF_F_MMAPABLE, and the fixed user address bml uses.
	arenaProbeUserVMStart = 0x100001000
	// BPF_F_SLEEPABLE, the only flag a syscall program profile carries (kfuncInitialSpec).
	arenaProbeProgFlags = 16
	// BPF_LOG_LEVEL1 (cilium's LogLevelBranch), bml's LV_LOG_1.
	arenaProbeLogLevel = ebpf.LogLevelBranch
)

// arenaKfuncProtos are the only spellings the recipe accepts (bml: spell[] and the
// return checks in lv_arena_kfunc_load).
var arenaKfuncProtos = map[string]kfuncRecipeProto{
	arenaAllocPages: {"ptr:void", []string{"ptr:void", "ptr:void", "u32", "i32", "u64"}},
	arenaFreePages:  {"void", []string{"ptr:void", "ptr:void", "u32"}},
}

func isArenaKfunc(name string) bool {
	_, ok := arenaKfuncProtos[name]
	return ok
}

// arenaKfuncDeps separates the target reads and syscalls so the recipe can be
// tested without root. create returns the map fd, or a unix.Errno.
type arenaKfuncDeps struct {
	spec   func() (*btf.Spec, error)
	create func() (int, error)
	close  func(fd int)
	load   func(*ebpf.ProgramSpec) (io.Closer, error)
}

// liveArenaKfuncDeps performs no reader or syscall work itself; the closures run
// only inside loadArenaKfunc.
func liveArenaKfuncDeps() arenaKfuncDeps {
	return arenaKfuncDeps{
		spec:   vmlinux,
		create: createArenaProbeMap,
		close:  func(fd int) { _ = unix.Close(fd) },
		load: func(ps *ebpf.ProgramSpec) (io.Closer, error) {
			// Log level 1 from the first attempt, like bml's LV_LOG_1. Level 2 prints more
			// lines and so changes the "(N line(s) omitted)" count in the Unknown text.
			p, err := ebpf.NewProgramWithOptions(ps, ebpf.ProgramOptions{LogLevel: arenaProbeLogLevel})
			return kfuncProgramHandle(p, err)
		},
	}
}

// arenaMapCreateAttr is the BPF_MAP_CREATE prefix of union bpf_attr up to map_extra
// (offset 64). The kernel treats the fields after it as zero.
type arenaMapCreateAttr struct {
	mapType, keySize, valueSize, maxEntries, mapFlags, innerMapFD, numaNode uint32
	mapName                                                                 [16]byte
	mapIfindex, btfFD, btfKeyTypeID, btfValueTypeID, btfVmlinuxValueTypeID  uint32
	mapExtra                                                                uint64
}

// createArenaProbeMap uses the raw syscall rather than ebpf.NewMap: cilium wraps the
// errno text (bml records the plain Go errno text) and may mmap an arena map.
func createArenaProbeMap() (int, error) {
	a := arenaMapCreateAttr{mapType: uint32(ebpf.Arena), maxEntries: 1, mapFlags: unix.BPF_F_MMAPABLE, mapExtra: arenaProbeUserVMStart}
	fd, _, errno := unix.Syscall(unix.SYS_BPF, uintptr(unix.BPF_MAP_CREATE), uintptr(unsafe.Pointer(&a)), unsafe.Sizeof(a))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

func arenaUnknown(format string, a ...any) error {
	return fmt.Errorf(format+": %w", append(a, requirements.ErrUnknown)...)
}

// arenaKfuncID is bml's dependency(): BTF, one FUNC by the exact name, a direct
// FUNC_PROTO and a valid ID, then the same prototype comparison as kfunc_protos.
func arenaKfuncID(d arenaKfuncDeps, name, ret string, args []string) (int32, error) {
	s, err := d.spec()
	if err == nil && s == nil {
		err = errors.New("no target BTF")
	}
	if err != nil {
		return 0, arenaUnknown("arena kfunc %s BTF unavailable: %v", name, err)
	}
	var fn *btf.Func
	if err := btfexact.TypeByName(s, name, &fn); err != nil {
		return 0, arenaUnknown("arena kfunc %s lookup: %v", name, err)
	}
	_, isProto := fn.Type.(*btf.FuncProto)
	id, err := s.TypeID(fn)
	if !isProto || err != nil || id == 0 || uint64(id) > math.MaxInt32 {
		return 0, arenaUnknown("arena kfunc %s invalid FUNC_PROTO/ID", name)
	}
	diffs, err := checkKfuncIn(s, name, ret, args)
	if err != nil {
		return 0, err
	}
	if len(diffs) != 0 {
		return 0, arenaUnknown("arena kfunc %s prototype: %s", name, strings.Join(diffs, "; "))
	}
	return int32(id), nil
}

// loadArenaKfunc runs after kfuncInitialSpec has accepted the canonical profile.
func loadArenaKfunc(p requirements.KfuncProfile, name, ret string, args []string, d arenaKfuncDeps) (bool, error) {
	if p.Kind != "syscall" {
		return false, arenaUnknown("arena recipe needs original syscall context")
	}
	want, ok := arenaKfuncProtos[name]
	if !ok || want.ret != ret || !reflect.DeepEqual(want.args, args) {
		return false, arenaUnknown("no strict arena kfunc recipe for %s", name)
	}
	if d.spec == nil || d.create == nil || d.close == nil || d.load == nil {
		return false, errors.New("arena kfunc recipe: missing dependencies")
	}
	id, err := arenaKfuncID(d, name, ret, args)
	if err != nil {
		return false, err
	}
	fd, err := d.create()
	if err != nil {
		return false, arenaUnknown("arena recipe map create: %v", err)
	}
	defer d.close(fd)
	insns := asm.Instructions{asm.LoadMapPtr(asm.R1, fd), asm.Mov.Imm(asm.R2, 0), asm.Mov.Imm(asm.R3, 1)}
	if name == arenaAllocPages {
		insns = append(insns, asm.Mov.Imm(asm.R4, -1), asm.Mov.Imm(asm.R5, 0))
	}
	insns = append(insns,
		asm.Instruction{OpCode: asm.Call.Op(asm.ImmSource), Src: asm.PseudoKfuncCall, Constant: int64(id)},
		asm.Mov.Imm(asm.R0, 0), asm.Return())
	ps := &ebpf.ProgramSpec{Name: "arena_probe", Type: ebpf.Syscall, Flags: arenaProbeProgFlags, License: "GPL", Instructions: insns}
	prog, err := d.load(ps)
	if err == nil && prog != nil {
		// bml closes the program fd without reading the result (lv_close); so does this recipe.
		_ = prog.Close()
		return true, nil
	}
	if err == nil {
		err = errors.New("load returned no program")
	}
	return classifyArenaKfuncLoad(name, err)
}

// classifyArenaKfuncLoad is bml's classify(): false only for the exact named
// denial with no other callee denial; anything else is Unknown with the load
// error's one-line summary (cilium's VerifierError.Error, not the full %+v log).
func classifyArenaKfuncLoad(name string, err error) (bool, error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		want := "calling kernel function " + name + " is not allowed"
		named, other := false, false
		for _, line := range ve.Log {
			s := strings.TrimRight(strings.TrimLeft(line, " \t"), " \t\n\r")
			if s == want {
				named = true
			} else if strings.Contains(s, "calling kernel function ") && strings.Contains(s, " is not allowed") {
				other = true
			}
		}
		if named && !other {
			return false, nil
		}
	}
	return false, arenaUnknown("arena kfunc load does not establish named permission denial: %s", err.Error())
}
