package requirements

// Derive program/map-field policy inputs from ELF instructions and BTF without
// changing requirements text. Follow pseudo calls and function addresses
// transitively, collecting maps referenced by ld_imm64 whose value STRUCT has
// direct bpf_timer or bpf_spin_lock members. Only derived makes an empty table
// authoritative; not_derived lacks ELF evidence, while failed retains a reason.
// See docs/requirements_format.md section 7.

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
)

// MapFieldState distinguishes authoritative derivation from absent or failed evidence.
type MapFieldState string

const (
	MapFieldsNotDerived MapFieldState = ""        // Parse(section) has not read ELF instructions or BTF.
	MapFieldsDerived    MapFieldState = "derived" // FromELF derived an authoritative Uses table.
	MapFieldsFailed     MapFieldState = "failed"  // FromELF failed to derive Uses; inspect Reason.
)

// MapFieldUse identifies a used map and its bpf_timer or bpf_spin_lock field.
type MapFieldUse struct {
	Map, Field string
}

// MapFields maps program symbols to uses in map/field order, with derivation state.
type MapFields struct {
	State  MapFieldState
	Uses   map[string][]MapFieldUse
	Reason string
}

// MapFieldPolicy reports whether the verifier accepts this field-bearing map
// for the program type. Indeterminate answers wrap ErrUnknown. Missing caps
// produce nonblocking map_field_unknown: the verifier loudly rejects a mismatch.
type MapFieldPolicy interface {
	AllowsMapField(progType string, progTypeID int64, field string) (bool, error)
}

// Target field names are BTF STRUCT names.
var mapFields = map[string]bool{"bpf_timer": true, "bpf_spin_lock": true}

// recordMapRef records ld_imm64 references to .maps. OBJECT relocations use the
// symbol name; SECTION relocations resolve symbol value plus immediate to a map
// OBJECT offset. Missing relocations with BPF_PSEUDO_MAP_FD or MAP_VALUE are
// unresolved map references and set mapErr.
func recordMapRef(f *elf.File, syms []elf.Symbol, x *fn, relocs map[uint64]elf.Symbol, at uint64, regs byte, immb []byte) {
	s, ok := relocs[at]
	if !ok {
		if src := regs >> 4; (src == 1 || src == 2) && x.mapErr == nil {
			x.mapErr = fmt.Errorf("%s: ld_imm64 at +%#x refers to a map (src_reg %d) without a relocation", x.name, at-x.start, src)
		}
		return
	}
	if int(s.Section) >= len(f.Sections) || s.Section == elf.SHN_UNDEF || f.Sections[s.Section].Name != ".maps" {
		return
	}
	if elf.ST_TYPE(s.Info) == elf.STT_OBJECT {
		x.maps = append(x.maps, s.Name)
		return
	}
	off := s.Value + uint64(binary.LittleEndian.Uint32(immb))
	for _, o := range syms {
		if o.Section == s.Section && elf.ST_TYPE(o.Info) == elf.STT_OBJECT && o.Value == off {
			x.maps = append(x.maps, o.Name)
			return
		}
	}
	if x.mapErr == nil {
		x.mapErr = fmt.Errorf("%s: ld_imm64 at +%#x refers to .maps offset %#x, which no map symbol starts at", x.name, at-x.start, off)
	}
}

// MapFieldUses derives uses per program FUNC symbol. Failure is an error, which
// callers must preserve as failed, never as an empty authoritative table.
func MapFieldUses(r io.ReaderAt) (map[string][]MapFieldUse, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fns, byStart, err := scanFuncs(f)
	if err != nil {
		return nil, err
	}
	// Follow reachable edges to collect used maps per program.
	used := map[string][]string{}
	var needed []string
	for _, x := range fns {
		seen := map[string]bool{}
		visited := map[*fn]bool{}
		var walkErr error
		var walk func(*fn)
		walk = func(g *fn) {
			if visited[g] || walkErr != nil {
				return
			}
			visited[g] = true
			if g.mapErr != nil {
				walkErr = g.mapErr
				return
			}
			for _, m := range g.maps {
				seen[m] = true
			}
			for _, c := range g.callees {
				walk(byStart[c])
			}
		}
		walk(x)
		if walkErr != nil {
			return nil, walkErr
		}
		for m := range seen {
			used[x.name] = append(used[x.name], m)
			needed = append(needed, m)
		}
	}
	fieldsOf := map[string][]string{}
	if len(needed) > 0 {
		// Sort maps before checking so the first failed map and diagnostic are
		// deterministic. bml copies MapFields.Reason into its matching diagnostic.
		sort.Strings(needed)
		fieldsOf, err = mapValueFields(f, needed)
		if err != nil {
			return nil, err
		}
	}
	out := map[string][]MapFieldUse{}
	for p, ms := range used {
		sort.Strings(ms)
		for _, m := range ms {
			for _, fl := range fieldsOf[m] {
				out[p] = append(out[p], MapFieldUse{Map: m, Field: fl})
			}
		}
	}
	return out, nil
}

// deriveMapFields implements FromELF's three-state derivation.
func deriveMapFields(r io.ReaderAt) (mf MapFields) {
	// This last-resort guard turns unexpected panics into failed evidence, not
	// a loader crash. Explicit bounds checks must still reject malformed input
	// without relying on a panic.
	defer func() {
		if p := recover(); p != nil {
			mf = MapFields{State: MapFieldsFailed, Reason: fmt.Sprintf("map-field derivation panicked: %v", p)}
		}
	}()
	uses, err := MapFieldUses(r)
	if err != nil {
		return MapFields{State: MapFieldsFailed, Reason: err.Error()}
	}
	return MapFields{State: MapFieldsDerived, Uses: uses}
}

// Minimal BTF reader for direct members of .maps value STRUCTs.

type mfType struct {
	kind    uint32
	name    string
	typeID  uint32
	members []struct {
		name   string
		typeID uint32
	}
	secinfo []uint32 // DATASEC VAR type ID.
}

// mapValueFields finds direct bpf_timer/bpf_spin_lock members of map value
// STRUCTs. Missing BTF, missing map VARs in .maps or unreadable kinds are errors.
// A definition without value (key_size/value_size form), or a non-STRUCT value,
// has no such fields.
func mapValueFields(f *elf.File, maps []string) (map[string][]string, error) {
	sec := f.Section(".BTF")
	if sec == nil {
		return nil, errors.New("the object has no .BTF section, so the map values cannot be read")
	}
	raw, err := sec.Data()
	if err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	if len(raw) < 24 || le.Uint16(raw) != 0xeb9f {
		return nil, errors.New(".BTF has no valid header")
	}
	hdrLen := le.Uint32(raw[4:])
	typeOff, typeLen := le.Uint32(raw[8:]), le.Uint32(raw[12:])
	strOff, strLen := le.Uint32(raw[16:]), le.Uint32(raw[20:])
	if uint64(hdrLen)+uint64(strOff)+uint64(strLen) > uint64(len(raw)) || uint64(hdrLen)+uint64(typeOff)+uint64(typeLen) > uint64(len(raw)) {
		return nil, errors.New(".BTF sections run past the data")
	}
	strs := raw[hdrLen+strOff : hdrLen+strOff+strLen]
	// Reject out-of-range names and missing NUL terminators: treating them as
	// empty names could hide a field. Bounds-check variable-sized payloads
	// before reading them, so corrupt BTF fails without a panic.
	str := func(off uint32) (string, error) {
		if int(off) >= len(strs) {
			return "", fmt.Errorf(".BTF name offset %d is outside the string section", off)
		}
		end := bytes.IndexByte(strs[off:], 0)
		if end < 0 {
			return "", fmt.Errorf(".BTF name at offset %d has no terminating NUL", off)
		}
		return string(strs[off : int(off)+end]), nil
	}
	types := []*mfType{{}}
	p, end := uint64(hdrLen)+uint64(typeOff), uint64(hdrLen)+uint64(typeOff)+uint64(typeLen)
	for p < end {
		if p+12 > end {
			return nil, fmt.Errorf(".BTF type data ends with %d stray byte(s)", end-p)
		}
		info := le.Uint32(raw[p+4:])
		name, err := str(le.Uint32(raw[p:]))
		if err != nil {
			return nil, err
		}
		t := &mfType{kind: (info >> 24) & 0x1f, name: name}
		vlen := uint64(info & 0xffff)
		t.typeID = le.Uint32(raw[p+8:])
		p += 12
		var extra uint64
		switch t.kind {
		case 1, 14, 17: // INT / VAR / DECL_TAG
			extra = 4
		case 3: // ARRAY
			extra = 12
		case 4, 5, 15, 19: // STRUCT / UNION / DATASEC / ENUM64
			extra = 12 * vlen
		case 6, 13: // ENUM / FUNC_PROTO
			extra = 8 * vlen
		case 2, 7, 8, 9, 10, 11, 12, 16, 18: // PTR / FWD / TYPEDEF / VOLATILE / CONST / RESTRICT / FUNC / FLOAT / TYPE_TAG
		default:
			return nil, fmt.Errorf(".BTF has kind %d, which this reader does not know", t.kind)
		}
		if p+extra > end {
			return nil, fmt.Errorf(".BTF type %d (kind %d) is truncated: needs %d byte(s), %d left", len(types), t.kind, extra, end-p)
		}
		switch t.kind {
		case 4, 5:
			for i := uint64(0); i < vlen; i++ {
				m := raw[p+12*i:]
				mn, err := str(le.Uint32(m))
				if err != nil {
					return nil, err
				}
				t.members = append(t.members, struct {
					name   string
					typeID uint32
				}{mn, le.Uint32(m[4:])})
			}
		case 15:
			for i := uint64(0); i < vlen; i++ {
				t.secinfo = append(t.secinfo, le.Uint32(raw[p+12*i:]))
			}
		}
		p += extra
		types = append(types, t)
	}
	get := func(id uint32) (*mfType, error) {
		if int(id) >= len(types) {
			return nil, fmt.Errorf(".BTF type id %d is out of range", id)
		}
		return types[id], nil
	}
	// Unwrap typedef, const, volatile, restrict and type_tag.
	strip := func(id uint32) (*mfType, error) {
		for n := 0; n < 32; n++ {
			t, err := get(id)
			if err != nil {
				return nil, err
			}
			switch t.kind {
			case 8, 9, 10, 11, 18:
				id = t.typeID
				continue
			}
			return t, nil
		}
		return nil, errors.New(".BTF modifier chain is too long")
	}
	vars := map[string]uint32{}
	for _, t := range types {
		if t.kind == 15 && t.name == ".maps" {
			for _, id := range t.secinfo {
				v, err := get(id)
				if err != nil {
					return nil, err
				}
				if v.kind == 14 {
					vars[v.name] = v.typeID
				}
			}
		}
	}
	out := map[string][]string{}
	for _, m := range maps {
		if _, done := out[m]; done {
			continue
		}
		defID, ok := vars[m]
		if !ok {
			return nil, fmt.Errorf("map %s has no VAR in the .BTF DATASEC .maps", m)
		}
		def, err := strip(defID)
		if err != nil {
			return nil, err
		}
		if def.kind != 4 {
			return nil, fmt.Errorf("map %s: its .BTF definition is not a struct", m)
		}
		fields := []string{}
		for _, mem := range def.members {
			if mem.name != "value" {
				continue
			}
			ptr, err := strip(mem.typeID)
			if err != nil {
				return nil, err
			}
			if ptr.kind != 2 {
				return nil, fmt.Errorf("map %s: the value member is not a pointer", m)
			}
			val, err := strip(ptr.typeID)
			if err != nil {
				return nil, err
			}
			if val.kind != 4 {
				break // Scalar and other non-STRUCT values have no target fields.
			}
			for _, vm := range val.members {
				mt, err := strip(vm.typeID)
				if err != nil {
					return nil, err
				}
				if mt.kind == 4 && mapFields[mt.name] {
					fields = append(fields, mt.name)
				}
			}
		}
		sort.Strings(fields)
		out[m] = fields
	}
	return out, nil
}

// mayHoldField selects maps that store record values. ringbuf and
// perf_event_array record declarations describe events, not stored map values;
// the kernel therefore has no value BTF for them.
func mayHoldField(m Map) bool {
	if !strings.HasPrefix(m.Value, "record:") {
		return false
	}
	switch m.MapType {
	case "ringbuf", "perf_event_array", "user_ringbuf": // user_ringbuf records likewise describe samples, not stored values.
		return false
	}
	return true
}

// checkMapFields checks derived map-field uses against capabilities.
func checkMapFields(req *Requirements, caps Capabilities, skip map[string]bool) ([]Unmet, error) {
	var out []Unmet
	if req.MapFields.State != MapFieldsDerived {
		why := req.MapFields.Reason
		if req.MapFields.State == MapFieldsNotDerived {
			why = "the requirements were parsed without the ELF (Parse), so map uses were not derived"
		}
		for _, m := range req.Maps {
			if mayHoldField(m) {
				out = append(out, Unmet{Kind: "map_field_unknown", Name: m.Symbol, Detail: why})
			}
		}
		return out, nil
	}
	mp, hasPolicy := capsAs[MapFieldPolicy](caps, QueryMapField)
	for _, p := range req.Programs {
		if skip[p.Symbol] {
			continue
		}
		for _, u := range req.MapFields.Uses[p.Symbol] {
			if !hasPolicy {
				out = append(out, Unmet{Kind: "map_field_unknown", Program: p.Symbol, Name: u.Map, Detail: u.Field + " × " + p.ProgType + ": no map-field probe"})
				continue
			}
			ok, err := mp.AllowsMapField(p.ProgType, p.ProgTypeID, u.Field)
			if errors.Is(err, ErrUnknown) {
				out = append(out, Unmet{Kind: "map_field_unknown", Program: p.Symbol, Name: u.Map, Detail: u.Field + " × " + p.ProgType + ": " + err.Error()})
				continue
			}
			if err != nil {
				return nil, err
			}
			if !ok {
				out = append(out, Unmet{Kind: "map_field", Program: p.Symbol, Name: u.Map, Detail: u.Field + " × " + p.ProgType})
			}
		}
	}
	return out, nil
}
