package requirements

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// BTFFeatureBlob constructs minimal raw BTF using feature f for BPF_BTF_LOAD.
// Loaders own probing, e.g. cilium NewHandleFromRawBTF without its marshal
// rewrites; this package only constructs bytes with the standard library.
// Supported features are int, ptr, const, array, struct, func, func_proto,
// func_global, var, datasec, decl_tag, type_tag, enum and enum64; others return an error.
// The decl_tag probe checks kind acceptance, not arg:nonnull semantics: its tag
// is not arg:-prefixed. Successful BTF loading does not prove tag interpretation.
func BTFFeatureBlob(f string) ([]byte, error) {
	b := &blob{strs: []byte{0}}
	intID := b.typ(b.str("int"), kindInfo(1, 0, false), 4, u32(0x01000020)) // INT, signed, 32 bits
	switch f {
	case "int":
	case "ptr":
		b.typ(0, kindInfo(2, 0, false), intID)
	case "const":
		b.typ(0, kindInfo(10, 0, false), intID)
	case "array":
		b.typ(0, kindInfo(3, 0, false), 0, u32(intID), u32(intID), u32(1)) // elem, index, nelems
	case "struct":
		b.typ(b.str("s"), kindInfo(4, 1, false), 4, u32(b.str("a")), u32(intID), u32(0))
	case "func", "func_proto", "func_global":
		proto := b.typ(0, kindInfo(13, 1, false), intID, u32(b.str("a")), u32(intID))
		linkage := uint32(0) // static
		if f == "func_global" {
			linkage = 1
		}
		b.typ(b.str("f"), kindInfo(12, linkage, false), proto)
	case "decl_tag":
		proto := b.typ(0, kindInfo(13, 1, false), intID, u32(b.str("a")), u32(intID))
		fn := b.typ(b.str("f"), kindInfo(12, 1, false), proto)         // global
		b.typ(b.str("ebpf_probe"), kindInfo(17, 0, false), fn, u32(0)) // DECL_TAG on argument zero.
	case "type_tag": // PTR -> TYPE_TAG -> INT, as for map-value kptr fields. Kernel
		// btf_find_kptr requires PTR -> TYPE_TAG with tag 'kptr'.
		tag := b.typ(b.str("ebpf_probe"), kindInfo(18, 0, false), intID)
		b.typ(0, kindInfo(2, 0, false), tag)
	case "enum": // a 4-byte ENUM with one enumerator (kernel_types enum fields).
		b.typ(b.str("e"), kindInfo(6, 1, false), 4, u32(b.str("E")), u32(0))
	case "enum64": // an 8-byte ENUM64 with one enumerator (name, lo32, hi32). A 64-bit kernel_types enum field is a raw ENUM of size 8 in the ELF, which cilium marshals as ENUM64 — so the kernel must accept ENUM64.
		b.typ(b.str("e"), kindInfo(19, 1, false), 8, u32(b.str("E")), u32(0), u32(0))
	case "var", "datasec":
		v := b.typ(b.str("v"), kindInfo(14, 0, false), intID, u32(1)) // global allocated
		if f == "datasec" {
			b.typ(b.str(".data"), kindInfo(15, 1, false), 4, u32(v), u32(0), u32(4))
		}
	default:
		return nil, fmt.Errorf("no probe blob for BTF feature %q", f)
	}
	return b.bytes(), nil
}

type blob struct {
	types, strs []byte
	n           uint32
}

func kindInfo(kind, vlen uint32, kflag bool) uint32 {
	i := kind<<24 | vlen&0xffff
	if kflag {
		i |= 1 << 31
	}
	return i
}

func u32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func (b *blob) str(s string) uint32 {
	off := uint32(len(b.strs))
	b.strs = append(append(b.strs, s...), 0)
	return off
}

// typ appends btf_type (name_off, info, size/type) and its payload, returning
// the new type ID.
func (b *blob) typ(name, info, sizeOrType uint32, extra ...[]byte) uint32 {
	b.types = append(b.types, u32(name)...)
	b.types = append(b.types, u32(info)...)
	b.types = append(b.types, u32(sizeOrType)...)
	for _, e := range extra {
		b.types = append(b.types, e...)
	}
	b.n++
	return b.n
}

func (b *blob) bytes() []byte {
	var out bytes.Buffer
	le := binary.LittleEndian
	binary.Write(&out, le, uint16(0xeB9F)) // magic
	out.WriteByte(1)                       // version
	out.WriteByte(0)                       // flags
	binary.Write(&out, le, uint32(24))     // hdr_len
	binary.Write(&out, le, uint32(0))      // type_off
	binary.Write(&out, le, uint32(len(b.types)))
	binary.Write(&out, le, uint32(len(b.types))) // str_off
	binary.Write(&out, le, uint32(len(b.strs)))
	out.Write(b.types)
	out.Write(b.strs)
	return out.Bytes()
}
