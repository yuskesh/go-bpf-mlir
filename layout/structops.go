package layout

import (
	"bytes"
	"debug/elf"
	"fmt"
	"strings"
)

// StructOpsTable describes one ELF struct_ops map (variable name is its
// symbol). Read .struct_ops.link/.struct_ops DATASEC VAR -> local STRUCT.
// Function-pointer members resolve .rel.struct_ops.link program symbols; char
// arrays decode to NUL for names such as tcp_congestion_ops.name. See
// docs/requirements_format.md section 12 maps.json struct_ops.
type StructOpsTable struct {
	Type string            // Local STRUCT name, also the kernel ops struct name.
	Data map[string]string // Character-array member names to NUL-terminated strings.
	Ops  map[string]string // Function-pointer members to relocation/program symbols.
}

// Spelling formats type=<T>;name=<N>;<member>=<program>;... with data and ops
// sorted by their respective member names.
func (t StructOpsTable) Spelling() string {
	var b strings.Builder
	b.WriteString("type=" + t.Type + ";")
	for _, k := range sortedKeys(t.Data) {
		b.WriteString(k + "=" + t.Data[k] + ";")
	}
	for _, k := range sortedKeys(t.Ops) {
		b.WriteString(k + "=" + t.Ops[k] + ";")
	}
	return b.String()
}

// StructOpsTables returns tables by variable name, or empty without struct_ops sections.
func StructOpsTables(elfBytes []byte) (map[string]StructOpsTable, error) {
	f, err := elf.NewFile(bytes.NewReader(elfBytes))
	if err != nil {
		return nil, err
	}
	out := map[string]StructOpsTable{}
	secIdx := map[int]string{}
	for i, s := range f.Sections {
		if s.Name == ".struct_ops.link" || s.Name == ".struct_ops" {
			secIdx[i] = s.Name
		}
	}
	if len(secIdx) == 0 {
		return out, nil
	}
	b, err := parseBTF(elfBytes)
	if err != nil {
		return nil, err
	}
	syms, err := f.Symbols()
	if err != nil {
		return nil, fmt.Errorf("the ELF symbol table cannot be read: %w", err)
	}
	for idx, secName := range secIdx {
		sec := f.Sections[idx]
		data, err := sec.Data()
		if err != nil {
			return nil, fmt.Errorf("%s cannot be read: %w", secName, err)
		}
		// Relocation r_offset -> symbol name. f.Symbols omits null, so indices start at one.
		rels := map[uint64]string{}
		for _, rs := range f.Sections {
			if rs.Type != elf.SHT_REL || int(rs.Info) != idx {
				continue
			}
			rd, err := rs.Data()
			if err != nil {
				return nil, fmt.Errorf("%s cannot be read: %w", rs.Name, err)
			}
			for i := 0; i+16 <= len(rd); i += 16 {
				off, info := f.ByteOrder.Uint64(rd[i:]), f.ByteOrder.Uint64(rd[i+8:])
				si := int(info >> 32)
				if si < 1 || si > len(syms) {
					return nil, fmt.Errorf("%s: relocation at %d names symbol %d outside the symbol table", rs.Name, off, si)
				}
				rels[off] = syms[si-1].Name
			}
		}
		for _, sy := range syms {
			if int(sy.Section) != idx || elf.ST_TYPE(sy.Info) != elf.STT_OBJECT {
				continue
			}
			vt, ok := b.vars[sy.Name]
			if !ok {
				return nil, fmt.Errorf("%s: variable %s has no BTF VAR", secName, sy.Name)
			}
			st := b.resolve(vt)
			if st.kind != kindStruct {
				return nil, fmt.Errorf("%s: variable %s is not a struct in the BTF", secName, sy.Name)
			}
			t := StructOpsTable{Type: st.name, Data: map[string]string{}, Ops: map[string]string{}}
			for _, m := range st.members {
				mt := b.resolve(m.typeID)
				pos := sy.Value + uint64(m.offset)
				switch mt.kind {
				case kindPtr:
					if p, ok := rels[pos]; ok {
						t.Ops[m.name] = p
					}
				case kindArray:
					n := uint64(b.sizeOf(m.typeID))
					if pos+n > uint64(len(data)) {
						return nil, fmt.Errorf("%s: member %s.%s is outside the section", secName, sy.Name, m.name)
					}
					raw := data[pos : pos+n]
					if i := bytes.IndexByte(raw, 0); i >= 0 {
						raw = raw[:i]
					}
					t.Data[m.name] = string(raw)
				}
			}
			out[sy.Name] = t
		}
	}
	return out, nil
}
