package requirements

import (
	"debug/dwarf"
	"fmt"
)

// dwarfPointerSpelling implements only format-18 user-probe ptr requests.
// It intentionally never calls Data.Type: pointee members are not evidence.
// Empty means Unknown; other mismatches use the existing uprobearg template.
func dwarfPointerSpelling(d *dwarf.Data, off dwarf.Offset) string {
	seen := map[dwarf.Offset]bool{}
	read := func(off dwarf.Offset) (*dwarf.Entry, int) {
		if seen[off] {
			return nil, 0
		}
		seen[off] = true
		r := d.Reader()
		r.Seek(off)
		e, err := r.Next()
		if err != nil || e == nil || e.Offset != off {
			return nil, 0
		}
		return e, r.AddressSize() // the referenced DIE's unit, including ref_addr
	}
	strip := func(off dwarf.Offset) (*dwarf.Entry, int) {
		for n := 0; n < 64; n++ {
			e, size := read(off)
			if e == nil {
				return nil, 0
			}
			switch e.Tag {
			case dwarf.TagTypedef, dwarf.TagConstType, dwarf.TagVolatileType, dwarf.TagRestrictType:
				if e.Tag != dwarf.TagTypedef && e.Val(dwarf.AttrType) == nil {
					// DWARF represents qualified void by an omitted type reference.
					return &dwarf.Entry{Offset: e.Offset, Tag: dwarf.TagUnspecifiedType}, size
				}
				next, ok := e.Val(dwarf.AttrType).(dwarf.Offset)
				if !ok {
					return nil, 0
				}
				off = next
			case dwarf.TagPointerType, dwarf.TagBaseType, dwarf.TagStructType,
				dwarf.TagClassType, dwarf.TagUnionType, dwarf.TagArrayType, dwarf.TagEnumerationType,
				dwarf.TagSubroutineType, dwarf.TagUnspecifiedType, dwarf.TagReferenceType, dwarf.TagRvalueReferenceType:
				return e, size
			default: // includes atomic: its semantics are outside this new request
				return nil, 0
			}
		}
		return nil, 0
	}
	e, width := strip(off)
	if e == nil {
		return ""
	}
	if e.Tag != dwarf.TagPointerType {
		return "non-pointer"
	}
	if value := e.Val(dwarf.AttrByteSize); value != nil {
		explicit, ok := value.(int64)
		if !ok || explicit <= 0 {
			return ""
		}
		// Width is displayed as decimal; never truncate a DWARF size to an int.
		if uint64(explicit) > uint64(^uint(0)>>1) {
			return ""
		}
		width = int(explicit)
	}
	if width <= 0 {
		return ""
	}
	depth := "1"
	if value := e.Val(dwarf.AttrType); value != nil {
		next, ok := value.(dwarf.Offset)
		if !ok {
			return ""
		}
		pointee, _ := strip(next)
		if pointee == nil {
			return ""
		}
		if pointee.Tag == dwarf.TagPointerType {
			depth = ">=2"
		}
	}
	if depth == "1" && width == 8 {
		return "ptr"
	}
	if depth == ">=2" {
		return fmt.Sprintf("ptr(depth>=2,width=%d)", width)
	}
	return fmt.Sprintf("ptr(depth=1,width=%d)", width)
}
