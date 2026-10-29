package bindrt

// Check caller map declarations against ELF requirements before loading, catching
// declarations changed without regenerating the object. Callers provide schema
// type spellings instead of reflection. See docs/requirements_format.md section 12.

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/yuskesh/go-bpf-mlir/layout"
	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// MapDecl describes one caller-declared map.
type MapDecl struct {
	Name       string  `json:"name"`            // Map symbol.
	Kind       string  `json:"kind"`            // Required map type name, using requirements spellings such as array or hash.
	Key        string  `json:"key"`             // Schema spelling (u32, i64, record:<S>, [N]iW); '-' for a keyless map.
	Value      string  `json:"value"`           // Schema spelling, as for Key.
	MaxEntries uint64  `json:"max_entries"`     // Declared element count.
	Flags      *uint64 `json:"flags,omitempty"` // Nil means flags 0; nonzero ELF flags then produce flags_undeclared.
	// Inner optionally checks the inner-map template against the format-12 innermap
	// row. Nil skips this check; mismatches or a missing ELF row produce inner.
	Inner *InnerDecl `json:"inner,omitempty"`
	// StructOps optionally checks the ELF .struct_ops.link global: local BTF
	// STRUCT name, character-array members and function-pointer relocations.
	// Nil skips this check; differences produce struct_ops.
	StructOps *StructOpsDecl `json:"struct_ops,omitempty"`
}

// StructOpsDecl uses schema core.maps[].struct_ops spellings. Name is valid only
// when the type has a name member; declaring it for bpf_dummy_ops is a mismatch.
type StructOpsDecl struct {
	Type string            `json:"type"`
	Name string            `json:"name,omitempty"`
	Ops  []StructOpsOpDecl `json:"ops"`
}

// StructOpsOpDecl associates a table member with its implementing program.
type StructOpsOpDecl struct {
	Member  string `json:"member"`
	Program string `json:"program"`
}

// spelling matches layout.StructOpsTable.Spelling; name is the data member.
func (d StructOpsDecl) spelling() string {
	t := layout.StructOpsTable{Type: d.Type, Data: map[string]string{}, Ops: map[string]string{}}
	if d.Name != "" {
		t.Data["name"] = d.Name
	}
	for _, o := range d.Ops {
		t.Ops[o.Member] = o.Program
	}
	return t.Spelling()
}

// InnerDecl describes an inner-map template using MapDecl spellings. Flags
// cannot be omitted.
type InnerDecl struct {
	Kind       string `json:"kind"`
	Key        string `json:"key"`
	Value      string `json:"value"`
	MaxEntries uint64 `json:"max_entries"`
	Flags      uint64 `json:"flags"`
}

// MapDeclOptions selects optional declaration checks.
type MapDeclOptions struct {
	// AllowUndeclared permits ELF maps absent from declarations. False checks both
	// directions; true supports callers that manage only a subset of maps.
	AllowUndeclared bool `json:"allow_undeclared,omitempty"`
	// Records declares sizes and members, checked against ELF BTF STRUCT names,
	// byte offsets and type spellings. Undeclared records are checked by name only.
	Records map[string]RecordDecl `json:"records,omitempty"`
	// Globals nil skips checking. Non-nil, including an empty array, checks each
	// declaration against ELF symbols, relocated BTF DATASEC VARs and integer
	// width/sign as layout.CheckGlobals does. Undeclared .rodata/.bss globals
	// are mismatches unless AllowUndeclaredGlobals is set.
	Globals []GlobalDecl `json:"globals,omitempty"`
	// AllowUndeclaredGlobals permits undeclared ELF globals independently of maps.
	AllowUndeclaredGlobals bool `json:"allow_undeclared_globals,omitempty"`
}

// GlobalDecl uses schema sections rodata/bss and integer spellings u8..i64.
// The be suffix is accepted but not checked: BTF does not encode endianness.
type GlobalDecl struct {
	Name    string `json:"name"`
	Section string `json:"section"`
	Type    string `json:"type"`
}

// RecordDecl describes size and members without padding. Members are sorted by
// offset for comparison. Types are u8..i64, [N]T, record:<T>, kptr:<T>,
// bpf_spin_lock or bpf_timer. kptr targets are outside the record closure.
// Integer be suffixes are accepted but not checked because BTF lacks endianness.
type RecordDecl = layout.RecordShape

// RecordMember describes a member of RecordDecl.
type RecordMember = layout.Member

// MapDecls is the maps.json declaration document for ebpf-precheck --maps.
// See docs/requirements_format.md section 12.
type MapDecls struct {
	MapDeclOptions
	Maps []MapDecl `json:"maps"`
}

// MarshalJSON preserves the distinction between Globals nil (skip checking,
// omit the key) and an empty array (declare no globals). Ordinary omitempty
// would silently drop the latter check. Key order follows struct field order.
func (d MapDecls) MarshalJSON() ([]byte, error) {
	type out struct {
		AllowUndeclared        bool                  `json:"allow_undeclared,omitempty"`
		Records                map[string]RecordDecl `json:"records,omitempty"`
		Globals                *[]GlobalDecl         `json:"globals,omitempty"`
		AllowUndeclaredGlobals bool                  `json:"allow_undeclared_globals,omitempty"`
		Maps                   []MapDecl             `json:"maps"`
	}
	o := out{AllowUndeclared: d.AllowUndeclared, Records: d.Records, AllowUndeclaredGlobals: d.AllowUndeclaredGlobals, Maps: d.Maps}
	if d.Globals != nil {
		g := d.Globals
		o.Globals = &g
	}
	return json.Marshal(o)
}

// ParseMapDecls rejects duplicate, case-mismatched and unknown keys, invalid
// UTF-8, trailing bytes and excessive depth using requirements.DecodeStrictJSON.
func ParseMapDecls(data []byte) (*MapDecls, error) {
	var d MapDecls
	if err := requirements.DecodeStrictJSON(data, &d); err != nil {
		return nil, fmt.Errorf("maps: %w", err)
	}
	return &d, nil
}

// MapDeclProblem reports a mismatch. Field names are the stable problem
// identifiers in docs/requirements_format.md section 12. Map identifies the map,
// record:<S> or global. struct_ops values use type=<T>;name=<N>;<member>=<program>;... .
type MapDeclProblem struct {
	Map      string `json:"map"`
	Field    string `json:"field"`
	Declared string `json:"declared"`
	ELF      string `json:"elf"`
}

func (p MapDeclProblem) String() string {
	switch p.Field {
	case "missing_in_elf":
		return fmt.Sprintf("map %s: declared (%s), but the ELF has no such map", p.Map, p.Declared)
	case "undeclared":
		return fmt.Sprintf("map %s: the ELF holds it (%s), but it is not declared", p.Map, p.ELF)
	case "flags_undeclared":
		return fmt.Sprintf("map %s: flags are not declared, but the ELF map has flags %s (omit flags only for maps whose flags are 0)", p.Map, p.ELF)
	case "decl", "format":
		return fmt.Sprintf("map %s: %s", p.Map, p.Declared)
	case "record":
		return fmt.Sprintf("%s: the same name with a different layout — declared %s, but the ELF BTF has %s", p.Map, p.Declared, p.ELF)
	case "record_missing":
		return fmt.Sprintf("%s: declared (%s), but the ELF BTF has no such struct", p.Map, p.Declared)
	case "global":
		return fmt.Sprintf("global %s: declared %s, but the ELF differs: %s", p.Map, p.Declared, p.ELF)
	case "global_missing_in_elf":
		return fmt.Sprintf("global %s: declared (%s), but the ELF has no such global in .rodata / .bss", p.Map, p.Declared)
	case "global_undeclared":
		return fmt.Sprintf("global %s: the ELF holds it (%s), but it is not declared", p.Map, p.ELF)
	case "inner":
		return fmt.Sprintf("map %s: inner map template declared %s, but the ELF has %s", p.Map, p.Declared, p.ELF)
	case "struct_ops":
		return fmt.Sprintf("map %s: struct_ops table declared %s, but the ELF has %s", p.Map, p.Declared, p.ELF)
	}
	return fmt.Sprintf("map %s: %s is %s in the declaration, but %s in the ELF", p.Map, p.Field, p.Declared, p.ELF)
}

// MapDeclError lists mismatches in declaration order, then undeclared ELF maps.
type MapDeclError struct{ Problems []MapDeclProblem }

func (e *MapDeclError) Error() string {
	var b strings.Builder
	b.WriteString("the map declarations differ from the ELF (regenerate the bindings from the same schema):")
	for _, p := range e.Problems {
		b.WriteString("\n  ")
		b.WriteString(p.String())
	}
	return b.String()
}

// CheckMapDecls parses then calls Parsed.CheckMapDecls; parse failures are
// RequirementsError.
func CheckMapDecls(elf []byte, decls []MapDecl, opt MapDeclOptions) error {
	p, err := Parse(elf)
	if err != nil {
		return err
	}
	return p.CheckMapDecls(decls, opt)
}

// CheckMapDecls compares declarations to requirements, returning MapDeclError.
// A kind mismatch suppresses later field comparisons for that map.
// USDT argument programs also emit __ebpf_usdt_spec_<program>, absent from the
// schema but included in the default bidirectional check. Declare it explicitly
// or use AllowUndeclared, which permits all undeclared maps, not just USDT maps.
// Reserved names never grant an automatic exemption.
func (p *Parsed) CheckMapDecls(decls []MapDecl, opt MapDeclOptions) error {
	var probs []MapDeclProblem
	add := func(m, f, d, e string) { probs = append(probs, MapDeclProblem{m, f, d, e}) }
	if p.req.Version < 2 {
		add("", "format", fmt.Sprintf("requirements version %d has no map definitions (rebuild the object)", p.req.Version), "")
		return &MapDeclError{probs}
	}
	rows := map[string]int{}
	for i, m := range p.req.Maps {
		rows[m.Symbol] = i
	}
	seen := map[string]bool{}
	for _, d := range decls {
		switch {
		case d.Name == "":
			add("", "decl", "a declaration without a name", "")
			continue
		case seen[d.Name]:
			add(d.Name, "decl", "declared twice", "")
			continue
		case d.Kind == "":
			seen[d.Name] = true
			add(d.Name, "decl", "declared without a kind (the kind is required — the key and value spellings alone do not tell an array from a per-CPU array)", "")
			continue
		}
		seen[d.Name] = true
		i, ok := rows[d.Name]
		if !ok {
			add(d.Name, "missing_in_elf", d.Kind, "")
			continue
		}
		row := p.req.Maps[i]
		if d.Kind != row.MapType {
			add(d.Name, "kind", d.Kind, row.MapType)
			continue
		}
		if d.Key != row.Key {
			add(d.Name, "key", d.Key, row.Key)
		}
		if d.Value != row.Value {
			add(d.Name, "value", d.Value, row.Value)
		}
		if d.MaxEntries != row.MaxEntries {
			add(d.Name, "max_entries", strconv.FormatUint(d.MaxEntries, 10), strconv.FormatUint(row.MaxEntries, 10))
		}
		if d.Flags != nil && *d.Flags != row.Flags {
			add(d.Name, "flags", strconv.FormatUint(*d.Flags, 10), strconv.FormatUint(row.Flags, 10))
		}
		// Omitted flags permit only zero ELF flags; flags such as BPF_F_NO_PREALLOC
		// must not silently disappear from the declaration.
		if d.Flags == nil && row.Flags != 0 {
			add(d.Name, "flags_undeclared", "", strconv.FormatUint(row.Flags, 10))
		}
		// Check an inner template only when declared. Differences or a missing
		// innermap row produce inner (format 12; specification section 12).
		if d.Inner != nil {
			decl := "kind=" + d.Inner.Kind + " key=" + d.Inner.Key + " value=" + d.Inner.Value + " max_entries=" + strconv.FormatUint(d.Inner.MaxEntries, 10) +
				" flags=" + strconv.FormatUint(d.Inner.Flags, 10)
			elfInner := "-"
			for _, im := range p.req.InnerMaps {
				if im.Outer == d.Name {
					elfInner = requirements.InnerMapSpelling(im)
				}
			}
			if decl != elfInner {
				add(d.Name, "inner", decl, elfInner)
			}
		}
		// Check declared struct_ops against the ELF .struct_ops.link global.
		// Section text alone cannot supply this check (format); a missing table
		// is represented as ELF '-'.
		if d.StructOps != nil {
			decl := d.StructOps.spelling()
			switch {
			case p.elf == nil:
				add(d.Name, "format", "struct_ops is declared, but only the requirements section was given (the struct_ops check needs the ELF)", "")
			default:
				tabs, err := layout.StructOpsTables(p.elf)
				if err != nil {
					add(d.Name, "format", "the ELF cannot be read for the struct_ops check: "+err.Error(), "")
					break
				}
				got := "-"
				if t, ok := tabs[d.Name]; ok {
					got = t.Spelling()
				}
				if decl != got {
					add(d.Name, "struct_ops", decl, got)
				}
			}
		}
	}
	probs = append(probs, p.checkRecords(opt.Records)...)
	probs = append(probs, p.checkGlobals(opt.Globals, opt.AllowUndeclaredGlobals)...)
	if !opt.AllowUndeclared {
		for _, m := range p.req.Maps {
			if !seen[m.Symbol] {
				add(m.Symbol, "undeclared", "", m.MapType)
			}
		}
	}
	if len(probs) > 0 {
		return &MapDeclError{probs}
	}
	return nil
}

// Global integer type spelling, accepting the be suffix.
var globalType = regexp.MustCompile(`^([ui])(8|16|32|64)(be)?$`)

// checkGlobals checks non-nil declarations against ELF in name order.
func (p *Parsed) checkGlobals(decls []GlobalDecl, allowUndeclared bool) []MapDeclProblem {
	if decls == nil {
		return nil
	}
	var probs []MapDeclProblem
	add := func(m, f, d, e string) { probs = append(probs, MapDeclProblem{m, f, d, e}) }
	if p.elf == nil {
		add("", "format", "globals are declared, but only the requirements section was given (the global check needs the ELF)", "")
		return probs
	}
	elfGlobals, err := layout.GlobalSymbols(p.elf)
	if err != nil {
		add("", "format", "the ELF cannot be read for the global check: "+err.Error(), "")
		return probs
	}
	sorted := append([]GlobalDecl(nil), decls...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	seen := map[string]bool{}
	for _, d := range sorted {
		spell := d.Section + " " + d.Type
		m := globalType.FindStringSubmatch(d.Type)
		switch {
		case d.Name == "":
			add("", "decl", "a global without a name", "")
			continue
		case seen[d.Name]:
			add(d.Name, "decl", "global declared twice", "")
			continue
		case d.Section != "rodata" && d.Section != "bss":
			seen[d.Name] = true
			add(d.Name, "decl", fmt.Sprintf("global section %q (want rodata or bss)", d.Section), "")
			continue
		case m == nil:
			seen[d.Name] = true
			add(d.Name, "decl", fmt.Sprintf("global type %q (want an integer spelling u8 … i64)", d.Type), "")
			continue
		}
		seen[d.Name] = true
		if _, ok := elfGlobals[d.Name]; !ok {
			add(d.Name, "global_missing_in_elf", spell, "")
			continue
		}
		bits, _ := strconv.Atoi(m[2])
		ps, err := layout.GlobalProblems(p.elf, layout.Global{Name: d.Name, Section: "." + d.Section, Size: uint32(bits / 8), Signed: m[1] == "i"})
		if err != nil {
			add(d.Name, "format", "the ELF cannot be read for the global check: "+err.Error(), "")
			continue
		}
		if len(ps) > 0 {
			add(d.Name, "global", spell, strings.Join(ps, "; "))
		}
	}
	if !allowUndeclared {
		names := make([]string, 0, len(elfGlobals))
		for n := range elfGlobals {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			if !seen[n] {
				add(n, "global_undeclared", "", strings.TrimPrefix(elfGlobals[n], "."))
			}
		}
	}
	return probs
}

// Declared member type spelling, accepting the be suffix.
var memberType = regexp.MustCompile(`^(\[[1-9][0-9]*\])*([ui](8|16|32|64)(be)?|(record|kptr):[A-Za-z_][A-Za-z0-9_]*)$|^bpf_spin_lock$|^bpf_timer$`)

// checkRecords checks declarations against ELF BTF STRUCTs in name order.
func (p *Parsed) checkRecords(recs map[string]RecordDecl) []MapDeclProblem {
	if len(recs) == 0 {
		return nil
	}
	var probs []MapDeclProblem
	add := func(m, f, d, e string) { probs = append(probs, MapDeclProblem{m, f, d, e}) }
	if p.elf == nil {
		add("", "format", "records are declared, but only the requirements section was given (the record check needs the ELF BTF)", "")
		return probs
	}
	lookup, err := layout.BTFRecords(p.elf)
	if err != nil {
		add("", "format", "the ELF BTF cannot be read for the record check: "+err.Error(), "")
		return probs
	}
	names := make([]string, 0, len(recs))
	for n := range recs {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		d := recs[n]
		key := "record:" + n
		if n == "" {
			add(key, "decl", "a record without a name", "")
			continue
		}
		if msg := recordDeclError(d); msg != "" {
			add(key, "decl", msg, "")
			continue
		}
		// Require the transitive record:<T> closure. Otherwise nested contents
		// would silently escape these per-record checks.
		if t := undeclaredNested(d, recs); t != "" {
			add(key, "decl", fmt.Sprintf("member type record:%s — the nested record %s must be declared in records too", t, t), "")
			continue
		}
		want := normalizeRecord(d)
		got, err := lookup(n)
		if errors.Is(err, layout.ErrNoRecord) {
			add(key, "record_missing", want.String(), "")
			continue
		}
		if err != nil {
			add(key, "format", err.Error(), "")
			continue
		}
		if want.String() != got.String() {
			add(key, "record", want.String(), got.String())
		}
	}
	return probs
}

// recordDeclError names duplicate members, unreadable types and duplicate
// offsets, or returns an empty string for a valid declaration.
func recordDeclError(d RecordDecl) string {
	names, offs := map[string]bool{}, map[uint32]bool{}
	for _, m := range d.Members {
		switch {
		case m.Name == "":
			return "a member without a name"
		case names[m.Name]:
			return fmt.Sprintf("member %s is declared twice", m.Name)
		case offs[m.Offset]:
			return fmt.Sprintf("two members at offset %d", m.Offset)
		case !memberType.MatchString(m.Type):
			return fmt.Sprintf("member %s has an unreadable type %q (u8…i64, [N]T, record:<T>, kptr:<T>, bpf_spin_lock, bpf_timer)", m.Name, m.Type)
		}
		names[m.Name], offs[m.Offset] = true, true
	}
	return ""
}

// beSuffix matches integer types, including array elements, not record names.
var beSuffix = regexp.MustCompile(`^((\[[0-9]+\])*[ui](8|16|32|64))be$`)

// normalizeRecord sorts by offset and removes integer be suffixes, since BTF
// does not encode endianness (specification section 12).
func normalizeRecord(d RecordDecl) RecordDecl {
	out := RecordDecl{Size: d.Size}
	for _, m := range d.Members {
		m.Type = beSuffix.ReplaceAllString(m.Type, "$1")
		out.Members = append(out.Members, m)
	}
	sort.SliceStable(out.Members, func(i, j int) bool { return out.Members[i].Offset < out.Members[j].Offset })
	return out
}

// nestedRecord extracts a record name after removing array prefixes.
var nestedRecord = regexp.MustCompile(`^(\[[0-9]+\])*record:(.+)$`)

// undeclaredNested returns the first referenced record missing from recs, or ''.
func undeclaredNested(d RecordDecl, recs map[string]RecordDecl) string {
	for _, m := range d.Members {
		if g := nestedRecord.FindStringSubmatch(m.Type); g != nil {
			if _, ok := recs[g[2]]; !ok {
				return g[2]
			}
		}
	}
	return ""
}
