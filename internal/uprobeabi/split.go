package uprobeabi

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"fmt"
	"hash/crc32"
	"strings"
)

// DebugFile returns the bytes of the separate debug file named by the binary's .gnu_debuglink (a base name). nil means no separate DWARF is
// looked up. The frontend looks only in the binary's directory (never /usr/lib/debug — the generated files must not depend on the host).
type DebugFile func(name string) ([]byte, error)

// dwarfOf returns the DWARF of the binary: its own .debug_info when it has one (the debug file is then not read), otherwise the separate debug
// file bound to it by the same rules as bpf-mlir's pre-load check (go/requirements — the canon at load time): the debug file's GNU build ID
// must equal the binary's byte for byte, and the CRC32 in the binary's .gnu_debuglink must equal the CRC32 of the whole debug file.
// Symbols, file offsets and the sha256 always come from the binary.
func dwarfOf(f *elf.File, debug DebugFile) (*dwarf.Data, error) {
	if hasDebugInfo(f) {
		return f.DWARF()
	}
	if debug == nil {
		return nil, fmt.Errorf("no .debug_info and no separate debug file lookup")
	}
	name, crc, err := debugLink(f)
	if err != nil {
		return nil, err
	}
	id, err := buildID(f)
	if err != nil {
		return nil, fmt.Errorf("the binary: %w", err)
	}
	b, err := debug(name)
	if err != nil {
		return nil, fmt.Errorf("the separate debug file %s (named by .gnu_debuglink): %w", name, err)
	}
	df, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("the separate debug file %s is not an ELF file: %w", name, err)
	}
	if df.Class != f.Class || df.Data != f.Data || df.Machine != f.Machine {
		return nil, fmt.Errorf("the separate debug file %s has a different ELF class, data or machine", name)
	}
	got, err := buildID(df)
	if err != nil {
		return nil, fmt.Errorf("the separate debug file %s: %w", name, err)
	}
	if !bytes.Equal(got, id) {
		return nil, fmt.Errorf("the separate debug file %s has build ID %x, but the binary's is %x (the debug file of a different build)", name, got, id)
	}
	if c := crc32.ChecksumIEEE(b); c != crc {
		return nil, fmt.Errorf("the separate debug file %s has CRC32 %08x, but the binary's .gnu_debuglink says %08x", name, c, crc)
	}
	if !hasDebugInfo(df) {
		return nil, fmt.Errorf("the separate debug file %s has no .debug_info", name)
	}
	return df.DWARF()
}

func hasDebugInfo(f *elf.File) bool {
	for _, s := range f.Sections {
		if (s.Name == ".debug_info" || s.Name == ".zdebug_info") && s.Type != elf.SHT_NOBITS && s.Size > 0 {
			return true
		}
	}
	return false
}

// uniqueSection returns the only section named name (nil if there is none) and an error if there are several.
func uniqueSection(f *elf.File, name string) (*elf.Section, error) {
	var found *elf.Section
	for _, s := range f.Sections {
		if s.Name == name {
			if found != nil {
				return nil, fmt.Errorf("several %s sections", name)
			}
			found = s
		}
	}
	return found, nil
}

// debugLink reads .gnu_debuglink: a NUL-terminated base name, padding to 4 bytes, and the CRC32 in the file's byte order.
func debugLink(f *elf.File) (string, uint32, error) {
	s, err := uniqueSection(f, ".gnu_debuglink")
	if err != nil {
		return "", 0, err
	}
	if s == nil {
		return "", 0, fmt.Errorf("no .debug_info and no .gnu_debuglink")
	}
	b, err := s.Data()
	if err != nil || s.Type != elf.SHT_PROGBITS || len(b) > 4096 {
		return "", 0, fmt.Errorf("an invalid .gnu_debuglink")
	}
	n := bytes.IndexByte(b, 0)
	end := (n + 4) &^ 3
	if n <= 0 || end+4 != len(b) {
		return "", 0, fmt.Errorf("an invalid .gnu_debuglink")
	}
	name := string(b[:n])
	if strings.ContainsRune(name, '/') || name == "." || name == ".." {
		return "", 0, fmt.Errorf(".gnu_debuglink names %q, which is not a file name in the binary's directory", name)
	}
	return name, f.ByteOrder.Uint32(b[end:]), nil
}

// buildID returns the descriptor of the one GNU build ID note (NT_GNU_BUILD_ID) in .note.gnu.build-id.
func buildID(f *elf.File) ([]byte, error) {
	s, err := uniqueSection(f, ".note.gnu.build-id")
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, fmt.Errorf("no GNU build ID")
	}
	b, err := s.Data()
	if err != nil || s.Type != elf.SHT_NOTE || len(b) > 4096 {
		return nil, fmt.Errorf("an invalid GNU build ID note")
	}
	var id []byte
	for len(b) > 0 {
		if len(b) < 12 {
			return nil, fmt.Errorf("an invalid GNU build ID note")
		}
		bo := f.ByteOrder
		nsz, dsz, typ := uint64(bo.Uint32(b)), uint64(bo.Uint32(b[4:])), bo.Uint32(b[8:])
		na, da := (nsz+3)&^3, (dsz+3)&^3
		if 12+na+da > uint64(len(b)) {
			return nil, fmt.Errorf("an invalid GNU build ID note")
		}
		if nsz == 4 && bytes.Equal(b[12:16], []byte("GNU\x00")) && typ == 3 {
			if id != nil || dsz == 0 || dsz > 64 {
				return nil, fmt.Errorf("an invalid GNU build ID note")
			}
			id = append([]byte(nil), b[12+na:12+na+dsz]...)
		}
		b = b[12+na+da:]
	}
	if id == nil {
		return nil, fmt.Errorf("no GNU build ID")
	}
	return id, nil
}
