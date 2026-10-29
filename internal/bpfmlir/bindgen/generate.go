// Package bindgen generates typed cilium/ebpf bindings from the canonical schema.
// Schema offsets are authoritative: explicit padding and offset-based decoders
// prevent Go's layout rules from silently dropping C padding.
package bindgen

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/format"
	"sort"
	"strings"
)

type Input struct {
	Package    string
	SchemaJSON []byte
	ObjectPath string // Relative ELF path used by generated go:embed.
	// Hex SHA-256 of the schema file bytes, verified against the ELF by the caller.
	// Generated SchemaSHA256 is checked against .ebpf_requirements before loading.
	SchemaSHA256 string
}

// Schema core only; telemetry and extensions are not read.

type schema struct {
	Version int `json:"version"`
	Core    struct {
		Records  []record  `json:"records"`
		Maps     []mapDecl `json:"maps"`
		Programs []program `json:"programs"`
		Globals  []global  `json:"globals"`
	} `json:"core"`
}

// global represents core.globals. ELF symbols, rather than schema offsets, determine byte positions.
type global struct {
	Name    string  `json:"name"`
	Section string  `json:"section"` // "rodata" | "bss"
	Type    intType `json:"type"`
	Note    string  `json:"note"`
}

type intType struct {
	Kind       string   `json:"kind"`
	Bits       uint32   `json:"bits"`
	Signed     bool     `json:"signed"`
	Endianness string   `json:"endianness"`
	Alignment  uint32   `json:"alignment"`
	Count      uint64   `json:"count"`
	Element    *intType `json:"element"`
	Symbol     string   `json:"symbol"`
	Struct     string   `json:"struct"` // Kernel struct pointed to by a kptr.
}

type field struct {
	Name   string  `json:"name"`
	Offset uint64  `json:"offset"`
	Expose string  `json:"expose"`
	Note   string  `json:"note"`
	Type   intType `json:"type"`
}

type record struct {
	Symbol    string  `json:"symbol"`
	ID        uint32  `json:"id"`
	Size      uint64  `json:"size"`
	MinSize   uint64  `json:"min_size"`
	Alignment uint32  `json:"alignment"`
	Fields    []field `json:"fields"`
	Note      string  `json:"note"`
}

type mapDecl struct {
	Symbol string `json:"symbol"`
	Kind   string `json:"kind"`
	Record string `json:"record"`
	Value  *struct {
		Kind   string `json:"kind"`
		Symbol string `json:"symbol"`
	} `json:"value"` // Value record for record_ref maps.
	Key *struct {
		Kind   string `json:"kind"`
		Symbol string `json:"symbol"`
	} `json:"key"` // Key record for record_ref maps.
	// Declared prog_array slots populated by the loader, matching tailslot requirements.
	Slots []struct {
		Index   uint32 `json:"index"`
		Program string `json:"program"`
	} `json:"slots"`
	// Operation table for struct_ops maps only.
	StructOps *struct {
		Type string `json:"type"`
		Name string `json:"name"`
		Ops  []struct {
			Member  string `json:"member"`
			Program string `json:"program"`
		} `json:"ops"`
	} `json:"struct_ops"`
}

// structOpsRegister mirrors REGISTER in Support/StructOpsTypes.def;
// TestStructOpsRegisterMatchesDef checks that agreement. Types marked none, such
// as bpf_dummy_ops, cannot register: omit their maps from Objects and remove them
// in LoadCollectionSpec. This avoids populateStructOps failing the entire load
// with -EOPNOTSUPP while allowing programs to load for test run.
var structOpsRegister = map[string]string{
	"tcp_congestion_ops": "link",
	"sched_ext_ops":      "link",
	"io_uring_bpf_ops":   "link",
	"bpf_dummy_ops":      "none",
}

type program struct {
	Name string `json:"name"`
	Kind string `json:"kind"`
}

// Type mapping.

func goScalar(t intType) (string, error) {
	if t.Kind != "int" {
		return "", fmt.Errorf("non-scalar type: %s", t.Kind)
	}
	prefix := "uint"
	if t.Signed {
		prefix = "int"
	}
	switch t.Bits {
	case 8, 16, 32, 64:
		return fmt.Sprintf("%s%d", prefix, t.Bits), nil
	}
	return "", fmt.Errorf("unsupported width: %d", t.Bits)
}

// opaqueFields maps spin_lock/timer schema kinds to BTF struct names; Go cannot access these holes.
var opaqueFields = map[string]string{"spin_lock": "bpf_spin_lock", "timer": "bpf_timer"}

// opaqueSizes matches abi/uapi.tsv uapistruct byte sizes, checked by unit tests.
var opaqueSizes = map[string]uint64{"spin_lock": 4, "timer": 16}

// Referenced kptr holes use go/layout's KptrOpaque and KptrSize, checked by tests.
// They are not UAPI structs and therefore stay outside opaqueFields.
const (
	kptrOpaque          = "kptr"
	kptrHoleSize uint64 = 8
)

// Go spelling and occupied byte count.
func goType(t intType, sizes map[string]uint64) (string, uint64, error) {
	switch t.Kind {
	case "int":
		s, err := goScalar(t)
		return s, uint64(t.Bits / 8), err
	case "array":
		elem, esz, err := goType(*t.Element, sizes)
		if err != nil {
			return "", 0, err
		}
		return fmt.Sprintf("[%d]%s", t.Count, elem), t.Count * esz, nil
	case "record_ref":
		sz, ok := sizes[t.Symbol]
		if !ok {
			return "", 0, fmt.Errorf("unknown size of record %q", t.Symbol)
		}
		return exported(t.Symbol), sz, nil
	}
	return "", 0, fmt.Errorf("unknown type kind: %s", t.Kind)
}

// exported converts schema symbols into valid exported Go identifiers.
// Strip invalid characters: simply joining words in <unit>_dns_events would
// produce the invalid spelling <unit>DnsEvents.
func exported(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	})
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	out := b.String()
	if out == "" {
		return "X"
	}
	if out[0] >= '0' && out[0] <= '9' {
		return "X" + out // Identifiers cannot start with a digit.
	}
	return out
}

// Generation.

func Generate(in Input) ([]byte, error) {
	var s schema
	if err := json.Unmarshal(in.SchemaJSON, &s); err != nil {
		return nil, fmt.Errorf("cannot read schema: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("schema version must be 1 (got %d)", s.Version)
	}
	if len(in.SchemaSHA256) != 64 {
		return nil, fmt.Errorf("schema SHA-256 is required (got %q)", in.SchemaSHA256)
	}

	sizes := map[string]uint64{}
	for _, r := range s.Core.Records {
		sizes[r.Symbol] = r.Size
	}
	// struct_ops types must appear in the REGISTER mirror. Non-registerable maps are omitted from Objects.
	unregistered := map[string]bool{}
	var structOpsMaps []mapDecl
	for _, m := range s.Core.Maps {
		if m.StructOps == nil {
			continue
		}
		reg, ok := structOpsRegister[m.StructOps.Type]
		if !ok {
			return nil, fmt.Errorf("struct_ops map %q: type %q is not in the bindgen struct_ops table (StructOpsTypes.def)", m.Symbol, m.StructOps.Type)
		}
		if reg == "none" {
			unregistered[m.Symbol] = true
		}
		structOpsMaps = append(structOpsMaps, m)
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, `// Code generated by ebpf-bindgen. DO NOT EDIT.
//
// The schema is canonical; this file is derived. **Do not edit by hand.**
// Offsets and padding follow the schema declarations, independently of Go struct layout.
// A handwritten reader that omits C's internal padding can silently read the wrong bytes.
//
// No cgo, C source or MLIR is needed. cilium/ebpf handles loading and later operations.
package %s

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/yuskesh/go-bpf-mlir/bindrt"
	"github.com/yuskesh/go-bpf-mlir/layout"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

//go:embed %s
var objectELF []byte

// ObjectELF returns the embedded BPF ELF with BTF.
func ObjectELF() []byte { return objectELF }
`, in.Package, in.ObjectPath)

	// --- record structs + decoders ---
	recs := append([]record(nil), s.Core.Records...)
	recByName := map[string]record{}
	for _, r := range s.Core.Records {
		recByName[r.Symbol] = r
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Symbol < recs[j].Symbol })
	for _, r := range recs {
		name := exported(r.Symbol)
		fmt.Fprintf(&b, "\n// %s is schema record %q (size=%d", name, r.Symbol, r.Size)
		if r.MinSize != r.Size {
			fmt.Fprintf(&b, ", variable length, min=%d", r.MinSize)
		}
		b.WriteString(").\n")
		if r.Note != "" {
			fmt.Fprintf(&b, "// %s\n", r.Note)
		}
		fmt.Fprintf(&b, "type %s struct {\n", name)

		fields := append([]field(nil), r.Fields...)
		sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })
		// Go naturally aligns fields. Reject schema offsets not divisible by the Go
		// field alignment, or record sizes not divisible by struct alignment: Go would
		// insert padding and disagree. Reject here rather than defer to CheckLayout.
		for _, f := range fields {
			fa, err := goAlign(f.Type, recByName)
			if err != nil {
				return nil, fmt.Errorf("record %q field %q: %w", r.Symbol, f.Name, err)
			}
			if f.Offset%fa != 0 {
				return nil, fmt.Errorf("record %q field %q: offset %d is not a multiple of Go type alignment %d — not representable by a Go struct (unsupported by bindgen)", r.Symbol, f.Name, f.Offset, fa)
			}
		}
		if ra, err := recordAlign(r, recByName); err != nil {
			return nil, err
		} else if r.Size%ra != 0 {
			return nil, fmt.Errorf("record %q: size %d is not a multiple of Go struct alignment %d — Go would add tail padding (unsupported by bindgen)", r.Symbol, r.Size, ra)
		}
		var at uint64
		// Padding must use blank (_) fields. Nonblank unexported names such as _pad0
		// make encoding/binary panic when cilium Map.Lookup unmarshals into them.
		// Blank fields are skipped when reading and written as zero.
		for _, f := range fields {
			if f.Offset > at {
				fmt.Fprintf(&b, "\t_ [%d]byte // schema-declared padding, independent of Go layout\n", f.Offset-at)
				at = f.Offset
			}
			// spin_lock/timer are inaccessible tagged blank fields; layout.Check matches BTF members exactly.
			if btfName, ok := opaqueFields[f.Type.Kind]; ok {
				n := opaqueSizes[f.Type.Kind]
				fmt.Fprintf(&b, "\t_ [%d]byte `schema:%q opaque:%q` // %s — inaccessible to userspace (kernel lookup returns zero; the kernel ignores these bytes on writes)", n, f.Name, btfName, btfName)
				if f.Type.Kind == "timer" {
					b.WriteString(". **Updating this element from userspace stops an active timer** (measured on three kernels)")
				} else {
					b.WriteString(". A userspace update without the flag does not take the lock (measured)")
				}
				b.WriteString("\n")
				at = f.Offset + n
				continue
			}
			// Referenced kptr values are inaccessible holes; layout.Check matches PTR -> TYPE_TAG kptr -> STRUCT.
			if f.Type.Kind == "kptr" {
				fmt.Fprintf(&b, "\t_ [%d]byte `schema:%q opaque:%q` // kptr (reference to struct %s) — inaccessible to userspace (kernel lookup returns zero; "+
					"on userspace update or deletion, the kernel releases the stored reference through its dtor)\n", kptrHoleSize, f.Name, kptrOpaque, f.Type.Struct)
				at = f.Offset + kptrHoleSize
				continue
			}
			gt, sz, err := goType(f.Type, sizes)
			if err != nil {
				return nil, fmt.Errorf("record %q field %q: %w", r.Symbol, f.Name, err)
			}
			// Tags carry schema field names for layout.Check to match BTF members.
			// Nested records also carry a record tag for nominal BTF struct-name matching.
			if f.Type.Kind == "record_ref" {
				fmt.Fprintf(&b, "\t%s %s `schema:%q record:%q`", exported(f.Name), gt, f.Name, f.Type.Symbol)
			} else if rec := innerRecord(f.Type); rec != "" {
				// Record arrays carry the element record name for layout.Check's nominal BTF check.
				fmt.Fprintf(&b, "\t%s %s `schema:%q record:%q`", exported(f.Name), gt, f.Name, rec)
			} else {
				fmt.Fprintf(&b, "\t%s %s `schema:%q`", exported(f.Name), gt, f.Name)
			}
			if f.Note != "" {
				fmt.Fprintf(&b, " // %s", strings.ReplaceAll(f.Note, "\n", " "))
			}
			b.WriteString("\n")
			at = f.Offset + sz
		}
		if r.Size > at {
			fmt.Fprintf(&b, "\t_ [%d]byte // tail padding\n", r.Size-at)
		}
		b.WriteString("}\n")

		fmt.Fprintf(&b, "\n// Size%s is the schema-declared record size.\nconst Size%s = %d\n",
			name, name, r.Size)

		// Schema expose=str generates a convenience method reading through the first NUL.
		for _, f := range fields {
			if f.Expose != "str" || f.Type.Kind != "array" || f.Type.Element == nil ||
				f.Type.Element.Bits != 8 {
				continue
			}
			fn := exported(f.Name)
			fmt.Fprintf(&b, `
// %sString reads %s as a NUL-terminated string (schema expose = "str").
func (v *%s) %sString() string {
	buf := make([]byte, 0, %d)
	for _, c := range v.%s {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
`, fn, f.Name, name, fn, f.Type.Count, fn)
		}

		// Decode by offsets, independently of Go struct layout.
		fmt.Fprintf(&b, `
// Decode reads raw ring-buffer bytes. **Offsets follow the schema declarations**;
// reading does not depend on Go struct layout.
func (v *%s) Decode(b []byte) error {
	if len(b) < %d {
		return fmt.Errorf("%s: %%d bytes available (need at least %d bytes)", len(b))
	}
`, name, r.MinSize, r.Symbol, r.MinSize)
		for _, f := range fields {
			if err := emitDecode(&b, f, sizes, r); err != nil {
				return nil, err
			}
		}
		b.WriteString("\treturn nil\n}\n")
	}

	// --- Objects ---
	b.WriteString("\n// Objects holds loaded programs and maps. Tags are ELF symbol names.\ntype Objects struct {\n")
	progs := append([]program(nil), s.Core.Programs...)
	sort.Slice(progs, func(i, j int) bool { return progs[i].Name < progs[j].Name })
	for _, p := range progs {
		fmt.Fprintf(&b, "\t%s *ebpf.Program `ebpf:%q`\n", exported(p.Name), p.Name)
	}
	var maps []mapDecl
	for _, m := range s.Core.Maps {
		if !unregistered[m.Symbol] { // LoadCollectionSpec removes maps of non-registerable struct_ops types.
			maps = append(maps, m)
		}
	}
	sort.Slice(maps, func(i, j int) bool { return maps[i].Symbol < maps[j].Symbol })
	for _, m := range maps {
		fmt.Fprintf(&b, "\t%s *ebpf.Map `ebpf:%q`\n", exported(m.Symbol), m.Symbol)
	}
	// .bss globals are read after load. Configure .rodata before load via RodataConfig; the kernel freezes it afterward.
	globals := append([]global(nil), s.Core.Globals...)
	sort.Slice(globals, func(i, j int) bool { return globals[i].Name < globals[j].Name })
	for _, g := range globals {
		if g.Section == "bss" {
			fmt.Fprintf(&b, "\t%s *ebpf.Variable `ebpf:%q` // .bss global\n", exported(g.Name), g.Name)
		}
	}
	b.WriteString("}\n")

	// Declared prog_array slots, in schema map/slot order matching tailslot requirements.
	type tslot struct {
		m, p string
		i    uint32
	}
	var tslots []tslot
	progNames := map[string]bool{}
	for _, p := range progs {
		progNames[p.Name] = true
	}
	for _, m := range s.Core.Maps {
		ss := append(m.Slots[:0:0], m.Slots...)
		sort.Slice(ss, func(i, j int) bool { return ss[i].Index < ss[j].Index })
		for _, q := range ss {
			if !progNames[q.Program] {
				return nil, fmt.Errorf("prog_array %q slot %d: program %q is not in core.programs — the bindings would not load it", m.Symbol, q.Index, q.Program)
			}
			tslots = append(tslots, tslot{m.Symbol, q.Program, q.Index})
		}
	}
	if len(tslots) > 0 {
		b.WriteString(`
// TailSlots lists schema-declared prog_array slots, in the embedded ELF requirements' tailslot-row order (format 7).
func TailSlots() []requirements.TailSlot {
	return []requirements.TailSlot{
`)
		for _, t := range tslots {
			fmt.Fprintf(&b, "\t\t{Map: %q, Slot: %d, Program: %q},\n", t.m, t.i, t.p)
		}
		b.WriteString(`	}
}

// CheckTailSlotsOf checks that ELF requirements tailslot rows exactly match TailSlots and every ELF program
// belongs to these bindings (all programs are loaded).
// go/bindrt owns the check.
func CheckTailSlotsOf(elf []byte) error {
	return bindrt.CheckTailSlots(elf, TailSlots(), []string{
`)
		for _, p := range progs {
			fmt.Fprintf(&b, "\t\t%q,\n", p.Name)
		}
		b.WriteString(`	})
}

// CheckTailSlots applies CheckTailSlotsOf to the embedded ELF.
func CheckTailSlots() error { return CheckTailSlotsOf(objectELF) }

// updateTailSlot sets one slot; package tests inject failure here. It is not a generated API.
var updateTailSlot = func(m *ebpf.Map, slot uint32, p *ebpf.Program) error { return m.Update(slot, p, ebpf.UpdateAny) }

// LoadObjectsWithTailSlotsUnchecked checks slots, loads and assigns all programs and maps to o, and sets only declared slots, **without checking requirements**.
// LoadObjectsWithTailSlots is the default checked entry point.
// The caller attaches programs. **Keep o (the prog_array map) open while attached**: entries disappear when the last userspace reference closes.
// A slot-setting failure closes o and returns an error. Undeclared slots are not set.
func LoadObjectsWithTailSlotsUnchecked(o *Objects, opts *ebpf.CollectionOptions) error {
	if err := CheckTailSlots(); err != nil {
		return err
	}
	spec, err := LoadCollectionSpec()
	if err != nil {
		return fmt.Errorf("cannot parse embedded ELF: %w", err)
	}
	if err := spec.LoadAndAssign(o, opts); err != nil {
		return err
	}
	for _, s := range []struct {
		m    *ebpf.Map
		slot uint32
		p    *ebpf.Program
		name string
	}{
`)
		for _, t := range tslots {
			fmt.Fprintf(&b, "\t\t{o.%s, %d, o.%s, %q},\n", exported(t.m), t.i, exported(t.p), t.m+"["+fmt.Sprint(t.i)+"] = "+t.p)
		}
		b.WriteString(`	} {
		if err := updateTailSlot(s.m, s.slot, s.p); err != nil {
			o.Close()
			return fmt.Errorf("tail-call slot %s: %w", s.name, err)
		}
	}
	return nil
}

// LoadObjectsWithTailSlots is the default load entry: precheckTarget checks requirements against caps and returns *TargetError for a blocking mismatch, before creating any kernel objects or slots.
// Otherwise it loads as LoadObjectsWithTailSlotsUnchecked does and returns nonblocking Unmet (Unknown, for the caller to record). Nil caps is an error; only Unchecked entry points skip the check.
func LoadObjectsWithTailSlots(o *Objects, opts *ebpf.CollectionOptions, caps requirements.Capabilities) ([]requirements.Unmet, error) {
	rest, err := precheckTarget(caps)
	if err != nil {
		return nil, err
	}
	return rest, LoadObjectsWithTailSlotsUnchecked(o, opts)
}
`)
	}

	// Schema and layout checks.
	fmt.Fprintf(&b, `
// SchemaSHA256 is the SHA-256 of the schema file used to generate the bindings.
const SchemaSHA256 = %q

// CheckSchemaOf checks that the schema SHA-256 in ELF %s matches the one used
// to generate the bindings. Rebuilding only the ELF is rejected before load.
// go/bindrt owns the check.
func CheckSchemaOf(elf []byte) error {
	return bindrt.CheckSchema(elf, SchemaSHA256, "rebuild both from the same schema (ebpf-compile and ebpf-bindgen)")
}

// RecordLayouts lists each record's Go layout; layout.Check compares it with ELF BTF.
func RecordLayouts() []layout.Record {
	return []layout.Record{
`, in.SchemaSHA256, "`.ebpf_requirements`")
	for _, r := range recs {
		name := exported(r.Symbol)
		fmt.Fprintf(&b, "\t\t{Symbol: %q, Size: Size%s, New: func() layout.Decoder { return new(%s) }},\n", r.Symbol, name, name)
	}
	b.WriteString(`	}
}
`)
	// Record-valued maps also require the .maps value PTR -> record binding.
	// Record keys use layout.MapValue with Member=key. Schemas without these
	// bindings retain their existing generated output.
	var mvs []mapDecl
	for _, m := range s.Core.Maps {
		if (m.Value != nil && m.Value.Kind == "record_ref") || (m.Key != nil && m.Key.Kind == "record_ref") {
			mvs = append(mvs, m)
		}
	}
	sort.Slice(mvs, func(i, j int) bool { return mvs[i].Symbol < mvs[j].Symbol })
	if len(mvs) == 0 {
		b.WriteString(`
// CheckLayout compares embedded ELF BTF with the bindings' record layout (size, field offsets, and Decode reads).
// BTF (ebpf-compile) and bindings (ebpf-bindgen) are separate implementations of the same schema.
func CheckLayout() error { return layout.Check(objectELF, RecordLayouts()) }
`)
	} else {
		hasKey := false
		for _, m := range mvs {
			hasKey = hasKey || (m.Key != nil && m.Key.Kind == "record_ref")
		}
		if hasKey {
			// Change the description only for schemas with record keys; preserve value-only output.
			b.WriteString(`
// MapValueRecords lists maps with record keys or values and their records; layout.CheckMapValues checks ELF BTF .maps.
// Member = "key" denotes a map key; an empty Member denotes a value.
func MapValueRecords() []layout.MapValue {
	return []layout.MapValue{
`)
		} else {
			b.WriteString(`
// MapValueRecords lists record-valued maps and their records; layout.CheckMapValues checks ELF BTF .maps.
func MapValueRecords() []layout.MapValue {
	return []layout.MapValue{
`)
		}
		for _, m := range mvs {
			if m.Key != nil && m.Key.Kind == "record_ref" {
				fmt.Fprintf(&b, "\t\t{Map: %q, Record: %q, Member: \"key\"},\n", m.Symbol, m.Key.Symbol)
			}
			if m.Value != nil && m.Value.Kind == "record_ref" {
				fmt.Fprintf(&b, "\t\t{Map: %q, Record: %q},\n", m.Symbol, m.Value.Symbol)
			}
		}
		b.WriteString(`	}
}

// CheckLayout compares embedded ELF BTF with the bindings' record layout (size, field offsets, and Decode reads).
// BTF (ebpf-compile) and bindings (ebpf-bindgen) are separate implementations of the same schema.
// Record equality alone cannot reject an ELF connecting a map value to a different record, so also check the map-value association.
func CheckLayout() error {
	if err := layout.Check(objectELF, RecordLayouts()); err != nil {
		return err
	}
	return layout.CheckMapValues(objectELF, MapValueRecords())
}
`)
	}

	if len(globals) > 0 {
		if err := emitGlobals(&b, globals, len(tslots) > 0); err != nil {
			return nil, err
		}
	}

	b.WriteString(`
// LoadCollectionSpec parses the embedded ELF. **Root privilege is not needed**.
// **Low-level API caution**: directly calling spec.LoadAndAssign does not check requirements. The caller must first call CheckTarget(caps).
// Only generated LoadObjects entry points guarantee that skipping checks requires an Unchecked name; this does not cover every loading path.
// This only reads ELF/BTF, without accessing the kernel. A schema mismatch between ELF and bindings is rejected before parsing.
func LoadCollectionSpec() (*ebpf.CollectionSpec, error) {
	if err := CheckSchemaOf(objectELF); err != nil {
		return nil, err
	}
`)
	if len(unregistered) == 0 {
		b.WriteString(`	return ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectELF))
}
`)
	} else {
		// Remove non-registerable struct_ops maps (REGISTER none, such as bpf_dummy_ops).
		// LoadCollectionSpec already set program AttachTo from .struct_ops.link
		// relocations, so programs can load without unsupported map population.
		b.WriteString(`	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(objectELF))
	if err != nil {
		return nil, err
	}
	// Do not load struct_ops maps whose type the kernel refuses to register; load their programs only, for test run.
`)
		var names []string
		for n := range unregistered {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			fmt.Fprintf(&b, "\tdelete(spec.Maps, %q)\n", n)
		}
		b.WriteString("\treturn spec, nil\n}\n")
	}
	if len(structOpsMaps) > 0 {
		b.WriteString(`
// StructOpsMember pairs one struct_ops table member with its implementing program.
type StructOpsMember struct{ Member, Program string }

// StructOpsTable describes one schema struct_ops map. Register is "link" (registration via BPF_LINK_CREATE; the caller uses
// link.AttachStructOps; generated code does not attach), or "none" (kernel refuses registration; do not load the map, use programs for test run only).
type StructOpsTable struct {
	Map, Type, Name, Register string
	Members                   []StructOpsMember
}

// StructOps lists schema struct_ops maps in schema map order.
func StructOps() []StructOpsTable {
	return []StructOpsTable{
`)
		for _, m := range structOpsMaps {
			fmt.Fprintf(&b, "\t\t{Map: %q, Type: %q, Name: %q, Register: %q, Members: []StructOpsMember{", m.Symbol, m.StructOps.Type, m.StructOps.Name, structOpsRegister[m.StructOps.Type])
			for i, o := range m.StructOps.Ops {
				if i > 0 {
					b.WriteString(", ")
				}
				fmt.Fprintf(&b, "{%q, %q}", o.Member, o.Program)
			}
			b.WriteString("}},\n")
		}
		b.WriteString("\t}\n}\n")
	}
	b.WriteString(`
// TargetError is a blocking requirements mismatch (requirements.Unmet.BlocksLoad). No kernel objects have been created.
// Alias of go/bindrt's type, shared by all generated packages.
type TargetError = bindrt.TargetError

// CheckTarget checks embedded ELF requirements against caps (FromELF includes inferred map-field use) and returns all Unmet.
// No kernel objects are created. The caller supplies caps (live probes or records). Nil is an error, not a request to skip checks.
// Recorded caps retain answers for the recorded privilege (probed_as). If load privilege differs, the caller must use requirements.RecordedCaps.ForLoad(load privilege, live caps)
// to re-probe privilege-dependent queries in the loading process. This function does not do that automatically.
// go/bindrt owns the check.
func CheckTarget(caps requirements.Capabilities) ([]requirements.Unmet, error) {
	return bindrt.CheckTarget(objectELF, caps)
}

// PrecheckError means prechecking itself failed at the default load entry: a caps probe error, unreadable requirements, nil caps, etc.
// Loading the embedded program has not begun (probes may create kernel objects such as maps). This differs from a known mismatch (*TargetError); Unwrap follows the cause
// (probe errors may wrap *ebpf.VerifierError; callers should identify PrecheckError before VerifierError).
// Alias of go/bindrt's type.
type PrecheckError = bindrt.PrecheckError

// precheckTarget starts the default checked load path: CheckTarget, then *TargetError for any BlocksLoad Unmet, otherwise the nonblocking Unmet (Unknown).
// Failure of the check itself is *PrecheckError.
// go/bindrt owns the check.
func precheckTarget(caps requirements.Capabilities) ([]requirements.Unmet, error) {
	return bindrt.Precheck(objectELF, caps)
}

`)
	if len(tslots) > 0 {
		b.WriteString(`
// LoadObjects is unavailable in this package because it declares tail-call slots. Leaving slots empty would silently make attached programs'
// tail calls take their fallback. Use LoadObjectsWithTailSlots.
func LoadObjects(o *Objects, opts *ebpf.CollectionOptions, caps requirements.Capabilities) ([]requirements.Unmet, error) {
	return nil, fmt.Errorf("this object declares tail-call slots; use LoadObjectsWithTailSlots (LoadObjects would leave them empty)")
}

// LoadObjectsUnchecked is also unavailable for the same reason; use LoadObjectsWithTailSlotsUnchecked.
func LoadObjectsUnchecked(o *Objects, opts *ebpf.CollectionOptions) error {
	return fmt.Errorf("this object declares tail-call slots; use LoadObjectsWithTailSlotsUnchecked (LoadObjectsUnchecked would leave them empty)")
}
`)
	} else {
		b.WriteString(`
// LoadObjectsUnchecked creates programs and maps from the embedded ELF and assigns them to o **without checking requirements**. LoadObjects is the default checked entry.
func LoadObjectsUnchecked(o *Objects, opts *ebpf.CollectionOptions) error {
	spec, err := LoadCollectionSpec()
	if err != nil {
		return fmt.Errorf("cannot parse embedded ELF: %w", err)
	}
	return spec.LoadAndAssign(o, opts)
}

// LoadObjects is the default load entry: precheckTarget checks requirements against caps and returns *TargetError for a blocking mismatch before creating kernel objects.
// Otherwise it loads as LoadObjectsUnchecked does and returns nonblocking Unmet (Unknown, for the caller to record). Nil caps is an error; only Unchecked entries skip the check.
func LoadObjects(o *Objects, opts *ebpf.CollectionOptions, caps requirements.Capabilities) ([]requirements.Unmet, error) {
	rest, err := precheckTarget(caps)
	if err != nil {
		return nil, err
	}
	return rest, LoadObjectsUnchecked(o, opts)
}
`)
	}
	b.WriteString(`
// Close closes assigned kernel resources.
func (o *Objects) Close() error {
	var first error
	closeOne := func(c interface{ Close() error }) {
		if c == nil {
			return
		}
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
`)
	for _, p := range progs {
		fmt.Fprintf(&b, "\tcloseOne(o.%s)\n", exported(p.Name))
	}
	for _, m := range maps {
		fmt.Fprintf(&b, "\tcloseOne(o.%s)\n", exported(m.Symbol))
	}
	b.WriteString("\treturn first\n}\n")

	// Always reference binary so generation cannot leave an unused import.
	b.WriteString("\nvar _ = binary.LittleEndian\n")

	out, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("cannot format generated Go: %w\n%s", err, b.String())
	}
	return out, nil
}

// emitGlobals generates core.globals checks and minimal typed access:
//   - Globals/CheckGlobals independently compare symbols, BTF DATASEC and schema.
//   - RodataConfig/LoadObjectsWithRodata set .rodata before load, after matching
//     cilium VariableSpecs with ELF symbols.
//   - Read<Name> reads .bss globals after load.
//
// LoadObjects retains the ELF defaults for .rodata.
func emitGlobals(b *bytes.Buffer, globals []global, hasTailSlots bool) error {
	b.WriteString(`
// Globals lists schema core.globals; layout.CheckGlobals compares ELF symbols and BTF DATASEC.
func Globals() []layout.Global {
	return []layout.Global{
`)
	var rodata []global
	for _, g := range globals {
		if g.Section != "rodata" && g.Section != "bss" {
			return fmt.Errorf("global %q: section %q (expected rodata or bss)", g.Name, g.Section)
		}
		if _, err := goScalar(g.Type); err != nil {
			return fmt.Errorf("global %q: %w", g.Name, err)
		}
		fmt.Fprintf(b, "\t\t{Name: %q, Section: %q, Size: %d, Signed: %v},\n", g.Name, "."+g.Section, g.Type.Bits/8, g.Type.Signed)
		if g.Section == "rodata" {
			rodata = append(rodata, g)
		}
	}
	b.WriteString(`	}
}

// CheckGlobals compares embedded ELF global symbols and BTF DATASEC with schema declarations.
// cilium overwrites var offsets using ELF symbols when DATASEC size is zero, so a BTF offset mismatch is not visible at load.
func CheckGlobals() error { return layout.CheckGlobals(objectELF, Globals()) }

// checkVariableSpec compares cilium VariableSpec section, size and offset with the schema and ELF symbols, independently checking the loader's interpretation.
// go/bindrt owns the check; this is glue extracting values from cilium VariableSpec.
func checkVariableSpec(spec *ebpf.CollectionSpec, g layout.Global) (*ebpf.VariableSpec, error) {
	vs := spec.Variables[g.Name]
	var v *bindrt.Variable
	if vs != nil {
		v = &bindrt.Variable{Section: vs.SectionName, Size: vs.Size(), Offset: vs.Offset}
	}
	if err := bindrt.CheckVariable(objectELF, g, v); err != nil {
		return nil, err
	}
	return vs, nil
}
`)
	if len(rodata) > 0 {
		b.WriteString(`
// RodataConfig configures .rodata globals before load. The kernel freezes .rodata after load (updates return EPERM).
type RodataConfig struct {
`)
		for _, g := range rodata {
			gt, _ := goScalar(g.Type)
			fmt.Fprintf(b, "\t%s %s `schema:%q`", exported(g.Name), gt, g.Name)
			if g.Note != "" {
				fmt.Fprintf(b, " // %s", strings.ReplaceAll(g.Note, "\n", " "))
			}
			b.WriteString("\n")
		}
		b.WriteString(`}

// LoadObjectsWithRodataUnchecked checks globals, sets .rodata globals from c, then creates programs/maps and assigns them to o **without checking requirements**.
// LoadObjectsWithRodata is the default checked entry.
func LoadObjectsWithRodataUnchecked(o *Objects, opts *ebpf.CollectionOptions, c RodataConfig) error {
`)
		if hasTailSlots {
			// Packages declaring tail slots reject loaders without slot configuration.
	// Combined .rodata and slot configuration is not implemented.
			b.WriteString(`	return fmt.Errorf("this object declares tail-call slots; LoadObjectsWithRodataUnchecked would leave them empty (an entry with both .rodata and slots is not implemented)")
}
`)
		} else {
			b.WriteString(`	if err := CheckGlobals(); err != nil {
		return err
	}
	spec, err := LoadCollectionSpec()
	if err != nil {
		return fmt.Errorf("cannot parse embedded ELF: %w", err)
	}
	gs := map[string]layout.Global{}
	for _, g := range Globals() {
		gs[g.Name] = g
	}
`)
			for _, g := range rodata {
				fmt.Fprintf(b, `	if vs, err := checkVariableSpec(spec, gs[%q]); err != nil {
		return err
	} else if err := vs.Set(c.%s); err != nil {
		return fmt.Errorf("global %s: %%w", err)
	}
`, g.Name, exported(g.Name), g.Name)
			}
			b.WriteString("\treturn spec.LoadAndAssign(o, opts)\n}\n")
		}
		b.WriteString(`
// LoadObjectsWithRodata is the default load entry: precheckTarget, then LoadObjectsWithRodataUnchecked. A blocking mismatch returns *TargetError before creating kernel objects. Nil caps is an error.
func LoadObjectsWithRodata(o *Objects, opts *ebpf.CollectionOptions, c RodataConfig, caps requirements.Capabilities) ([]requirements.Unmet, error) {
	rest, err := precheckTarget(caps)
	if err != nil {
		return nil, err
	}
	return rest, LoadObjectsWithRodataUnchecked(o, opts, c)
}
`)
	}
	for _, g := range globals {
		if g.Section != "bss" {
			continue
		}
		gt, _ := goScalar(g.Type)
		n := exported(g.Name)
		fmt.Fprintf(b, `
// Read%s reads .bss global %s after load.
func (o *Objects) Read%s() (%s, error) {
	var v %s
	if o.%s == nil {
		return v, fmt.Errorf("global %s: not loaded")
	}
	if o.%s.Size() != %d {
		return v, fmt.Errorf("global %s: loader size %%d (schema: %d)", o.%s.Size())
	}
	err := o.%s.Get(&v)
	return v, err
}
`, n, g.Name, n, gt, gt, n, g.Name, n, g.Type.Bits/8, g.Name, g.Type.Bits/8, n, n)
	}
	return nil
}

// emitDecodeElems generates reading lhs of type t from b[off:]: recurse over
// arrays, decode integer width/sign as little endian, and call Decode for records.
// off is a generated Go expression; depth identifies loop-index names.
func emitDecodeElems(b *bytes.Buffer, lhs string, t intType, off string, sizes map[string]uint64, depth int) error {
	switch t.Kind {
	case "int":
		gt, err := goScalar(t)
		if err != nil {
			return err
		}
		switch t.Bits {
		case 8:
			fmt.Fprintf(b, "%s%s = %s(b[%s])\n", indent(depth), lhs, gt, off)
		case 16, 32, 64:
			fmt.Fprintf(b, "%s%s = %s(binary.LittleEndian.Uint%d(b[%s:]))\n", indent(depth), lhs, gt, t.Bits, off)
		default:
			return fmt.Errorf("unsupported width: %d", t.Bits)
		}
	case "array":
		_, esz, err := goType(*t.Element, sizes)
		if err != nil {
			return err
		}
		iv := fmt.Sprintf("i%d", depth)
		fmt.Fprintf(b, "%sfor %s := 0; %s < %d; %s++ {\n", indent(depth), iv, iv, t.Count, iv)
		if err := emitDecodeElems(b, lhs+"["+iv+"]", *t.Element, fmt.Sprintf("%s+%s*%d", off, iv, esz), sizes, depth+1); err != nil {
			return err
		}
		fmt.Fprintf(b, "%s}\n", indent(depth))
	case "record_ref":
		sz, ok := sizes[t.Symbol]
		if !ok {
			return fmt.Errorf("unknown size of record %q", t.Symbol)
		}
		fmt.Fprintf(b, "%sif err := %s.Decode(b[%s : %s+%d]); err != nil {\n%s\treturn err\n%s}\n", indent(depth), lhs, off, off, sz, indent(depth), indent(depth))
	default:
		return fmt.Errorf("cannot read array element type kind %s", t.Kind)
	}
	return nil
}

func indent(depth int) string { return strings.Repeat("\t", depth+1) }

// goAlign computes generated Go type alignment, not schema alignment: integer
// width, array element alignment, or maximum record field alignment. Blank and
// opaque holes have alignment one.
func goAlign(t intType, recs map[string]record) (uint64, error) {
	switch t.Kind {
	case "int":
		return uint64(t.Bits / 8), nil
	case "array":
		return goAlign(*t.Element, recs)
	case "record_ref":
		r, ok := recs[t.Symbol]
		if !ok {
			return 0, fmt.Errorf("record %q is missing", t.Symbol)
		}
		return recordAlign(r, recs)
	case "spin_lock", "timer", "kptr": // kptr is also a blank hole.
		return 1, nil
	}
	return 0, fmt.Errorf("unknown type kind: %s", t.Kind)
}

func recordAlign(r record, recs map[string]record) (uint64, error) {
	a := uint64(1)
	for _, f := range r.Fields {
		fa, err := goAlign(f.Type, recs)
		if err != nil {
			return 0, err
		}
		if fa > a {
			a = fa
		}
	}
	return a, nil
}

// innerRecord returns the innermost array element's record name for the record
// tag used by layout.Check to match BTF array element struct names.
func innerRecord(t intType) string {
	for t.Kind == "array" && t.Element != nil {
		t = *t.Element
	}
	if t.Kind == "record_ref" {
		return t.Symbol
	}
	return ""
}

func emitDecode(b *bytes.Buffer, f field, sizes map[string]uint64, r record) error {
	name := exported(f.Name)
	switch f.Type.Kind {
	case "spin_lock", "timer", "kptr":
		// Do not read opaque holes, including kptr; kernel lookup returns them as zero.
		return nil
	case "int":
		gt, _ := goScalar(f.Type)
		switch f.Type.Bits {
		case 8:
			fmt.Fprintf(b, "\tv.%s = %s(b[%d])\n", name, gt, f.Offset)
		case 16:
			fmt.Fprintf(b, "\tv.%s = %s(binary.LittleEndian.Uint16(b[%d:]))\n", name, gt, f.Offset)
		case 32:
			fmt.Fprintf(b, "\tv.%s = %s(binary.LittleEndian.Uint32(b[%d:]))\n", name, gt, f.Offset)
		case 64:
			fmt.Fprintf(b, "\tv.%s = %s(binary.LittleEndian.Uint64(b[%d:]))\n", name, gt, f.Offset)
		}
	case "array":
		elem := *f.Type.Element
		if elem.Kind != "int" || elem.Bits != 8 {
			// Recursively decode non-byte arrays: wider integers, nested arrays and records.
			return emitDecodeElems(b, "v."+name, f.Type, fmt.Sprint(f.Offset), sizes, 0)
		}
		if elem.Signed {
			// Go char[] is int8[], so copy cannot be used.
			fmt.Fprintf(b, "\tfor i := 0; i < %d; i++ {\n\t\tv.%s[i] = int8(b[%d+i])\n\t}\n",
				f.Type.Count, name, f.Offset)
		} else {
			fmt.Fprintf(b, "\tcopy(v.%s[:], b[%d:%d])\n", name, f.Offset, f.Offset+f.Type.Count)
		}
	case "record_ref":
		sz := sizes[f.Type.Symbol]
		fmt.Fprintf(b, "\tif err := v.%s.Decode(b[%d : %d]); err != nil {\n\t\treturn err\n\t}\n",
			name, f.Offset, f.Offset+sz)
	}
	return nil
}
