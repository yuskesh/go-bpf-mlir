//go:build linux

// Package usdtattach implements the USDT ref_ctr loader contract on cilium
// v0.22; kernel/livecaps exposes the public facade. See
// docs/requirements_format.md section 8. It reads .note.stapsdt with the same
// requirements reader used by checking, adjusts PCs for prelink using the
// actual .stapsdt.base, resolves executable PT_LOAD file offsets, writes each
// 192-byte argument spec at key i in __ebpf_usdt_spec_<program>, then attaches
// Executable.Uprobe with Address, Cookie i and RefCtrOffset in note order.
// The caller must precheck before attaching and supply the same inode that
// was hashed, for example /proc/self/fd/N. Explicit Address bypasses cilium
// symbol lookup; the kernel still resolves the uprobe path.
package usdtattach

import (
	"debug/elf"
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// Options controls optional attachment behavior.
type Options struct {
	// PID selects a process; zero means all processes, as in cilium UprobeOptions.
	PID int
}

// Point describes one attached location; its index is the spec key and cookie.
type Point struct {
	Index         int
	PC            uint64 // Note PC before prelink adjustment.
	FileOffset    uint64 // File offset of the adjusted PC.
	Semaphore     uint64 // Note semaphore address, or zero when absent.
	SemFileOffset uint64 // Semaphore file offset (RefCtrOffset), or zero when absent.
	Args          string // Note argument descriptions.
	Spec          [requirements.USDTSpecSize]byte
	Unread        []int // Argument indices encoded as spec kind zero because their locations are
	// unsupported; precheck rejects these if the program reads them.
}

// Link owns all attached point uprobes; Close releases them all.
type Link struct {
	Points []Point
	Links  []link.Link
}

// Close releases all point uprobes.
func (l *Link) Close() error {
	var errs []error
	for _, k := range l.Links {
		if err := k.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	l.Links = nil
	return errors.Join(errs...)
}

// Points computes file/semaphore offsets and specs for all <provider>:<name>
// notes without attaching. This is loader computation, separate from checking.
func Points(binary, provider, name string) ([]Point, error) {
	f, err := elf.Open(binary)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	all, err := requirements.ReadUSDTPoints(f)
	if err != nil {
		return nil, err
	}
	var baseAddr uint64
	hasBase := false
	if s := f.Section(".stapsdt.base"); s != nil {
		baseAddr, hasBase = s.Addr, true
	}
	var out []Point
	for _, p := range all {
		if p.Provider != provider || p.Name != name {
			continue
		}
		pc := p.PC
		if hasBase && p.Base != 0 { // Apply libbpf-compatible prelink adjustment: actual .stapsdt.base
		// address minus the note's base.
			pc = pc + baseAddr - p.Base
		}
		off, err := fileOffset(f, pc, true)
		if err != nil {
			return nil, fmt.Errorf("%s:%s at pc 0x%x: %w", provider, name, p.PC, err)
		}
		pt := Point{Index: len(out), PC: p.PC, FileOffset: off, Semaphore: p.Semaphore, Args: p.Args}
		if p.Semaphore != 0 {
			if pt.SemFileOffset, err = fileOffset(f, p.Semaphore, false); err != nil {
				return nil, fmt.Errorf("%s:%s at pc 0x%x: semaphore: %w", provider, name, p.PC, err)
			}
		}
		pt.Spec, pt.Unread = requirements.EncodeUSDTSpec(p.Args)
		out = append(out, pt)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s has no USDT point %s:%s", binary, provider, name)
	}
	return out, nil
}

// fileOffset resolves an address within PT_LOAD (executable when exec).
// Semaphores must lie within Filesz, since the kernel updates the process
// mapping of that file-backed ref_ctr_offset page.
func fileOffset(f *elf.File, addr uint64, exec bool) (uint64, error) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || (exec && p.Flags&elf.PF_X == 0) {
			continue
		}
		if p.Vaddr <= addr && addr < p.Vaddr+p.Filesz {
			return addr - p.Vaddr + p.Off, nil
		}
	}
	return 0, fmt.Errorf("address 0x%x is in no loadable segment with file bytes", addr)
}

// Attach attaches every matching USDT point, using compiler specMap
// __ebpf_usdt_spec_<program>. Refuse counts above max_entries, as usdt_probe
// checking does. On failure, close points already attached.
func Attach(prog *ebpf.Program, specMap *ebpf.Map, binary, provider, name string, opts *Options) (*Link, error) {
	if prog == nil || specMap == nil {
		return nil, errors.New("usdtattach: nil program or spec map")
	}
	if specMap.ValueSize() != requirements.USDTSpecSize || specMap.KeySize() != 4 {
		return nil, fmt.Errorf("usdtattach: the spec map has key %d / value %d bytes, want 4 / %d (requirements_format.md §8)", specMap.KeySize(), specMap.ValueSize(), requirements.USDTSpecSize)
	}
	pts, err := Points(binary, provider, name)
	if err != nil {
		return nil, err
	}
	if uint32(len(pts)) > specMap.MaxEntries() {
		return nil, fmt.Errorf("usdtattach: %s:%s has %d points, but the spec map holds %d (max_points)", provider, name, len(pts), specMap.MaxEntries())
	}
	for _, p := range pts {
		if err := specMap.Put(uint32(p.Index), p.Spec[:]); err != nil {
			return nil, fmt.Errorf("usdtattach: spec of point %d: %w", p.Index, err)
		}
	}
	ex, err := link.OpenExecutable(binary)
	if err != nil {
		return nil, err
	}
	pid := 0
	if opts != nil {
		pid = opts.PID
	}
	l := &Link{Points: pts}
	sym := "usdt_" + strings.ReplaceAll(provider+"_"+name, ":", "_")
	for _, p := range pts {
		k, err := ex.Uprobe(sym, prog, &link.UprobeOptions{Address: p.FileOffset, PID: pid, Cookie: uint64(p.Index), RefCtrOffset: p.SemFileOffset})
		if err != nil {
			l.Close()
			return nil, fmt.Errorf("usdtattach: point %d (pc 0x%x): %w", p.Index, p.PC, err)
		}
		l.Links = append(l.Links, k)
	}
	return l, nil
}
