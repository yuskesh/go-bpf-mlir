package requirements

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// UprobeDebugFiles supplies immutable separate-DWARF bytes for this Check.
// The binary remains authoritative for its hash, symbol and attach address.
type UprobeDebugFiles interface {
	UprobeDebugFile(program string, buildID []byte) (io.ReaderAt, error)
}

const debugRawLimit = 268435456
const debugExpandedLimit = 536870912

// UprobeDebugKey is the cross-language caps query key, not a filesystem path.
func UprobeDebugKey(program string, id []byte) string { return program + "/" + hex.EncodeToString(id) }

type debugSourceError string

func (e debugSourceError) Error() string { return string(e) }
func (e debugSourceError) Unwrap() error { return ErrUnknown }

type namedDebugBytes struct {
	*bytes.Reader
	path string
}

func (r namedDebugBytes) Name() string { return r.path }

// BuildIDDebugPath constructs the only implicit lookup path. Empty root means
// disabled, not the default; callers choose /usr/lib/debug for an omitted root.
func BuildIDDebugPath(root string, id []byte) (string, error) {
	if len(id) < 1 || len(id) > 64 {
		return "", fmt.Errorf("GNU build ID must contain 1..64 bytes")
	}
	if root == "" {
		return "", debugSourceError("separate DWARF lookup is disabled")
	}
	h := hex.EncodeToString(id)
	return filepath.Join(root, ".build-id", h[:2], h[2:]+".debug"), nil
}

// ReadUprobeDebugFile snapshots a file once, closes it, and retains its path
// for Recorder. A relative path is resolved at this call, never during replay.
func ReadUprobeDebugFile(path string) (io.ReaderAt, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, debugSourceError("separate DWARF file is unavailable")
	}
	f, err := os.Open(abs)
	if err != nil {
		return nil, debugSourceError("separate DWARF file is unavailable")
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, debugSourceError("separate DWARF file is unavailable")
	}
	if st.Size() > debugRawLimit {
		return nil, debugSourceError("separate DWARF file exceeds 268435456 bytes")
	}
	b, err := io.ReadAll(io.LimitReader(f, debugRawLimit+1))
	if err != nil {
		return nil, debugSourceError("separate DWARF file is unavailable")
	}
	if len(b) > debugRawLimit {
		return nil, debugSourceError("separate DWARF file exceeds 268435456 bytes")
	}
	if int64(len(b)) != st.Size() {
		return nil, debugSourceError("separate DWARF file changed while reading")
	}
	return namedDebugBytes{bytes.NewReader(b), abs}, nil
}

// A source belongs to one attach check. Lazy resolution avoids a query for
// targets that do not read DWARF; multi shares the same immutable result.
type uprobeDWARFSource struct {
	body     *elf.File
	caps     Capabilities
	program  string
	resolved bool
	data     *dwarf.Data
	err      error
	kind     string
}

func hasDebugInfo(f *elf.File) bool {
	return f.Section(".debug_info") != nil || f.Section(".zdebug_info") != nil
}

func (s *uprobeDWARFSource) read() (*dwarf.Data, error) {
	if !s.resolved {
		s.resolved = true
		s.data, s.kind, s.err = s.selectSource()
	}
	return s.data, s.err
}

func (s *uprobeDWARFSource) selectSource() (*dwarf.Data, string, error) {
	bad := func(reason string) (*dwarf.Data, string, error) { return nil, "", debugSourceError(reason) }
	if s.body.Section(".gnu_debugaltlink") != nil {
		return bad("the binary contains unsupported .gnu_debugaltlink")
	}
	if hasDebugInfo(s.body) {
		d, err := s.body.DWARF()
		if err != nil {
			err = fmt.Errorf("no DWARF: %w", err)
		}
		return d, "", err
	}
	id, err := debugBuildID(s.body, "the binary")
	if err != nil {
		return nil, "", err
	}
	crc, hasCRC, err := debugLinkCRC(s.body)
	if err != nil {
		return nil, "", err
	}
	c, ok := capsAs[UprobeDebugFiles](s.caps, QueryUprobeDebug)
	if !ok {
		return bad("no separate DWARF capability")
	}
	r, err := c.UprobeDebugFile(s.program, append([]byte(nil), id...))
	if err != nil {
		if errors.Is(err, ErrUnknown) {
			return nil, "", err
		}
		return bad("separate DWARF query failed")
	}
	if r == nil {
		return bad("separate DWARF file is unavailable")
	}
	b, err := io.ReadAll(io.NewSectionReader(r, 0, debugRawLimit+1))
	if err != nil {
		return bad("separate DWARF query failed")
	}
	if len(b) > debugRawLimit {
		return bad("separate DWARF file exceeds 268435456 bytes")
	}
	f, err := elf.NewFile(bytes.NewReader(b))
	if err != nil {
		return bad("separate DWARF ELF is unreadable")
	}
	if f.Class != s.body.Class || f.Data != s.body.Data || f.Machine != s.body.Machine {
		return bad("separate DWARF ELF class, data or machine differs from the binary")
	}
	got, err := debugBuildID(f, "separate DWARF")
	if err != nil {
		return nil, "", err
	}
	if !bytes.Equal(got, id) {
		return nil, "uprobe_debug_build_id", fmt.Errorf("separate DWARF build ID is %x, want %x", got, id)
	}
	if hasCRC {
		if got := crc32.ChecksumIEEE(b); got != crc {
			return nil, "uprobe_debug_crc", fmt.Errorf("separate DWARF CRC32 is %08x, want %08x", got, crc)
		}
	}
	if f.Section(".gnu_debugaltlink") != nil {
		return bad("separate DWARF contains unsupported .gnu_debugaltlink")
	}
	for _, section := range f.Sections {
		if (section.Type == elf.SHT_REL || section.Type == elf.SHT_RELA) && int64(section.Info) < int64(len(f.Sections)) && isDebugSection(f.Sections[section.Info].Name) {
			return bad("separate DWARF contains unsupported relocations")
		}
	}
	if f.Section(".debug_types") != nil || f.Section(".zdebug_types") != nil {
		return bad("separate DWARF contains unsupported type units")
	}
	if err := debugSectionLimits(f, b); err != nil {
		return nil, "", err
	}
	if !hasDebugInfo(f) {
		return bad("separate DWARF has no debug information")
	}
	d, err := f.DWARF()
	if err != nil {
		err = fmt.Errorf("no DWARF: %w", err)
	}
	return d, "", err
}

func uniqueDebugSection(f *elf.File, name string) (*elf.Section, bool) {
	var selected *elf.Section
	for _, s := range f.Sections {
		if s.Name != name {
			continue
		}
		if selected != nil {
			return nil, false
		}
		selected = s
	}
	return selected, true
}

func debugBuildID(f *elf.File, owner string) ([]byte, error) {
	s, unique := uniqueDebugSection(f, ".note.gnu.build-id")
	invalid := debugSourceError(owner + " has an invalid GNU build ID note")
	if !unique {
		return nil, invalid
	}
	if s == nil {
		return nil, debugSourceError(owner + " has no GNU build ID")
	}
	if s.Type != elf.SHT_NOTE || s.Flags&elf.SHF_COMPRESSED != 0 || s.Size > 4096 {
		return nil, invalid
	}
	b, err := s.Data()
	if err != nil {
		return nil, invalid
	}
	var id []byte
	for len(b) > 0 {
		if len(b) < 12 {
			return nil, invalid
		}
		n, d, typ := uint64(f.ByteOrder.Uint32(b)), uint64(f.ByteOrder.Uint32(b[4:])), f.ByteOrder.Uint32(b[8:])
		na, da := (n+3)&^3, (d+3)&^3
		if na+da+12 > uint64(len(b)) {
			return nil, invalid
		}
		if n == 4 && bytes.Equal(b[12:16], []byte{'G', 'N', 'U', 0}) && typ == 3 {
			if id != nil || d < 1 || d > 64 {
				return nil, invalid
			}
			id = append([]byte(nil), b[12+na:12+na+d]...)
		}
		b = b[12+na+da:]
	}
	if id == nil {
		return nil, invalid
	}
	return id, nil
}

func debugLinkCRC(f *elf.File) (uint32, bool, error) {
	s, unique := uniqueDebugSection(f, ".gnu_debuglink")
	invalid := debugSourceError("the binary has an invalid GNU debuglink")
	if !unique {
		return 0, false, invalid
	}
	if s == nil {
		return 0, false, nil
	}
	if s.Type != elf.SHT_PROGBITS || s.Flags&elf.SHF_COMPRESSED != 0 || s.Size > 4096 {
		return 0, false, invalid
	}
	b, err := s.Data()
	if err != nil {
		return 0, false, invalid
	}
	nul := bytes.IndexByte(b, 0)
	if nul <= 0 {
		return 0, false, invalid
	}
	offset := (nul + 1 + 3) &^ 3
	if offset+4 != len(b) {
		return 0, false, invalid
	}
	return f.ByteOrder.Uint32(b[offset:]), true, nil
}

func isDebugSection(name string) bool {
	return strings.HasPrefix(name, ".debug_") || strings.HasPrefix(name, ".zdebug_")
}

func debugSectionLimits(f *elf.File, raw []byte) error {
	var total uint64
	invalid := debugSourceError("separate DWARF has an invalid compression header")
	for _, s := range f.Sections {
		if !isDebugSection(s.Name) {
			continue
		}
		if s.Type == elf.SHT_NOBITS {
			return debugSourceError("separate DWARF has a NOBITS debug section")
		}
		if s.Offset > uint64(len(raw)) || s.FileSize > uint64(len(raw))-s.Offset {
			return invalid
		}
		b := raw[s.Offset : s.Offset+s.FileSize]
		expanded := s.Size
		if s.Flags&elf.SHF_COMPRESSED != 0 {
			need := 12
			if f.Class == elf.ELFCLASS64 {
				need = 24
			}
			if len(b) < need {
				return invalid
			}
			typ := f.ByteOrder.Uint32(b)
			if typ == 2 {
				return debugSourceError("separate DWARF contains unsupported zstd compression")
			}
			if typ != 1 {
				return invalid
			}
			if f.Class == elf.ELFCLASS64 {
				expanded = f.ByteOrder.Uint64(b[8:])
			} else {
				expanded = uint64(f.ByteOrder.Uint32(b[4:]))
			}
		} else if strings.HasPrefix(s.Name, ".zdebug_") {
			if len(b) < 12 || !bytes.Equal(b[:4], []byte("ZLIB")) {
				return invalid
			}
			expanded = uint64(b[4])<<56 | uint64(b[5])<<48 | uint64(b[6])<<40 | uint64(b[7])<<32 | uint64(b[8])<<24 | uint64(b[9])<<16 | uint64(b[10])<<8 | uint64(b[11])
		}
		if expanded > debugExpandedLimit-total {
			return debugSourceError("separate DWARF expanded sections exceed 536870912 bytes")
		}
		total += expanded
	}
	return nil
}
