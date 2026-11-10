package bindgen

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/format"
	"go/token"
	"math"
	"regexp"
	"sort"

	"github.com/yuskesh/go-bpf-mlir/bindrt"
)

var runtimeImport = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~-]*(/[A-Za-z0-9_~][A-Za-z0-9._~-]*)+$`)

type ownedMap struct {
	Symbol     string   `json:"symbol"`
	Kind       string   `json:"kind"`
	MaxEntries *uint32  `json:"max_entries"`
	Flags      *uint32  `json:"flags"`
	MapExtra   *uint64  `json:"map_extra"`
	Key        *intType `json:"key"`
	Value      *intType `json:"value"`
}

func ownedSpelling(t *intType) (string, error) {
	if t == nil {
		return "-", nil
	}
	switch t.Kind {
	case "int":
		if t.Endianness != "" && t.Endianness != "little" {
			return "", fmt.Errorf("owned arena profile: endianness %q is unsupported; use little-endian map and record types", t.Endianness)
		}
		if t.Bits != 8 && t.Bits != 16 && t.Bits != 32 && t.Bits != 64 {
			return "", fmt.Errorf("unsupported integer width %d", t.Bits)
		}
		p := "u"
		if t.Signed {
			p = "i"
		}
		return fmt.Sprintf("%s%d", p, t.Bits), nil
	case "record_ref":
		return "record:" + t.Symbol, nil
	case "array":
		e, err := ownedSpelling(t.Element)
		return fmt.Sprintf("[%d]%s", t.Count, e), err
	default:
		return "", fmt.Errorf("unsupported map type %q", t.Kind)
	}
}

func generateOwnedArena(in Input) ([]byte, error) {
	if in.Profile != "go-arena-owned" {
		return nil, fmt.Errorf("unknown or missing bindgen profile %q", in.Profile)
	}
	if !runtimeImport.MatchString(in.ArenaRuntimeImport) {
		return nil, fmt.Errorf("arena runtime import is missing or invalid: %q", in.ArenaRuntimeImport)
	}
	if !token.IsIdentifier(in.Package) || token.Lookup(in.Package).IsKeyword() {
		return nil, fmt.Errorf("invalid package %q", in.Package)
	}
	if h, err := hex.DecodeString(in.SchemaSHA256); err != nil || len(h) != 32 {
		return nil, fmt.Errorf("schema SHA-256 is required")
	}
	var s schema
	if err := json.Unmarshal(in.SchemaJSON, &s); err != nil {
		return nil, fmt.Errorf("cannot read schema: %w", err)
	}
	if s.Version != 1 {
		return nil, fmt.Errorf("schema version must be 1")
	}
	if len(s.Core.Globals) != 0 {
		return nil, fmt.Errorf("owned arena profile does not support globals")
	}
	for _, p := range s.Core.Programs {
		if p.Kind != "socket_filter" && p.Kind != "syscall" {
			return nil, fmt.Errorf("owned arena profile program %q: unsupported kind %q", p.Name, p.Kind)
		}
	}
	var rich struct {
		Core struct {
			Maps []ownedMap `json:"maps"`
		} `json:"core"`
	}
	if err := json.Unmarshal(in.SchemaJSON, &rich); err != nil {
		return nil, fmt.Errorf("arena map declaration: %w", err)
	}
	var ar *ownedMap
	decl := bindrt.MapDecls{}
	ordinary := []ownedMap{}
	names := map[string]bool{}
	reserved := map[string]bool{"owner": true, "Close": true, "ReadArenaAt": true, "WriteArenaAt": true, "TestProgram": true, "RunProgram": true}
	for i, m := range rich.Core.Maps {
		if m.Symbol == "" || names[m.Symbol] {
			return nil, fmt.Errorf("duplicate or empty map name %q", m.Symbol)
		}
		names[m.Symbol] = true
		if m.MaxEntries == nil || m.Flags == nil {
			return nil, fmt.Errorf("map %q: max_entries and flags must be declared", m.Symbol)
		}
		if m.Kind == "arena" {
			if ar != nil {
				return nil, fmt.Errorf("owned arena profile requires exactly one arena")
			}
			ar = &rich.Core.Maps[i]
			if m.MapExtra == nil {
				return nil, fmt.Errorf("map %q: map_extra is required", m.Symbol)
			}
		} else {
			if m.MapExtra != nil {
				return nil, fmt.Errorf("map %q: map_extra is only supported for arena", m.Symbol)
			}
			if m.Kind != "array" && m.Kind != "hash" && m.Kind != "lru_hash" && m.Kind != "percpu_array" && m.Kind != "percpu_hash" {
				return nil, fmt.Errorf("map %q: unsupported owned map kind %q", m.Symbol, m.Kind)
			}
			n := exported(m.Symbol)
			if !token.IsIdentifier(n) || reserved[n] {
				return nil, fmt.Errorf("map %q: binding name is reserved or invalid", m.Symbol)
			}
			reserved[n] = true
			ordinary = append(ordinary, m)
		}
		key, err := ownedSpelling(m.Key)
		if err != nil {
			return nil, err
		}
		value, err := ownedSpelling(m.Value)
		if err != nil {
			return nil, err
		}
		flags := uint64(*m.Flags)
		decl.Maps = append(decl.Maps, bindrt.MapDecl{Name: m.Symbol, Kind: m.Kind, Key: key, Value: value, MaxEntries: uint64(*m.MaxEntries), Flags: &flags})
	}
	if ar == nil {
		return nil, fmt.Errorf("owned arena profile requires exactly one arena")
	}
	if *ar.MaxEntries == 0 || *ar.Flags != 1024 || *ar.MapExtra == 0 || *ar.MapExtra%4096 != 0 {
		return nil, fmt.Errorf("map %q: invalid fixed arena declaration", ar.Symbol)
	}
	decl.Records = map[string]bindrt.RecordDecl{}
	for _, r := range s.Core.Records {
		if r.Size > math.MaxUint32 {
			return nil, fmt.Errorf("record %q size exceeds uint32", r.Symbol)
		}
		d := bindrt.RecordDecl{Size: uint32(r.Size)}
		for _, f := range r.Fields {
			if f.Offset > math.MaxUint32 {
				return nil, fmt.Errorf("record %q member offset exceeds uint32", r.Symbol)
			}
			sp, err := ownedSpelling(&f.Type)
			if err != nil {
				return nil, err
			}
			d.Members = append(d.Members, bindrt.RecordMember{Name: f.Name, Offset: uint32(f.Offset), Type: sp})
		}
		decl.Records[r.Symbol] = d
	}
	declJSON, err := json.Marshal(decl)
	if err != nil {
		return nil, err
	}
	var b bytes.Buffer
	fmt.Fprintf(&b, `// Code generated by ebpf-bindgen (go-arena-owned). DO NOT EDIT.
// Stop all program use before Close; never unmap the owned address externally.
package %s
import (
 "bytes"
 _ "embed"
 "encoding/binary"
 "encoding/json"
 "errors"
 "fmt"
 "strings"
 "github.com/cilium/ebpf"
 "github.com/yuskesh/go-bpf-mlir/bindrt"
 "github.com/yuskesh/go-bpf-mlir/layout"
 "github.com/yuskesh/go-bpf-mlir/requirements"
 arena %q
)
//go:embed %s
var objectELF []byte
const SchemaSHA256 = %q
var _ = bytes.IndexByte
var _ = binary.LittleEndian
var _ = strings.TrimRight
`, in.Package, in.ArenaRuntimeImport, in.ObjectPath, in.SchemaSHA256)
	sizes := map[string]uint64{}
	for _, r := range s.Core.Records {
		sizes[r.Symbol] = r.Size
	}
	if err := emitRecordTypes(&b, s, sizes); err != nil {
		return nil, err
	}
	b.WriteString("\nfunc recordLayouts() []layout.Record { return []layout.Record{\n")
	for _, r := range s.Core.Records {
		fmt.Fprintf(&b, "{Symbol:%q, Size:Size%s, New:func() layout.Decoder{return new(%s)}},\n", r.Symbol, exported(r.Symbol), exported(r.Symbol))
	}
	b.WriteString("} }\n")
	b.WriteString("type Objects struct { owner *arena.ArenaObjects\n")
	sort.Slice(ordinary, func(i, j int) bool { return ordinary[i].Symbol < ordinary[j].Symbol })
	for _, m := range ordinary {
		fmt.Fprintf(&b, "%s *ebpf.Map\n", exported(m.Symbol))
	}
	b.WriteString("}\n")
	fmt.Fprintf(&b, `func arenaObject() (arena.ArenaObject,error) {
 var d bindrt.MapDecls
 if err:=json.Unmarshal([]byte(%q),&d);err!=nil{return arena.ArenaObject{},err}
 return arena.ArenaObject{ELF:objectELF,SchemaSHA256:SchemaSHA256,Maps:d.Maps,MapOptions:d.MapDeclOptions,Arena:arena.ArenaDecl{Name:%q,MaxEntries:%d,Flags:%d,MapExtra:%d}},nil
}
func LoadObjects(o *Objects, opts *ebpf.CollectionOptions, caps requirements.Capabilities) ([]requirements.Unmet,error) {
 if o==nil {return nil,fmt.Errorf("owned bindings: nil Objects")}
 if o.owner!=nil {return nil,fmt.Errorf("owned bindings: Objects already used")}
 if err:=bindrt.CheckSchema(objectELF,SchemaSHA256,"regenerate the owned bindings and ELF together");err!=nil{return nil,err}
 if err:=layout.Check(objectELF,recordLayouts());err!=nil{return nil,err}
 obj,err:=arenaObject();if err!=nil{return nil,err}
 owner,rest,err:=arena.LoadArena(obj,caps,opts);if err!=nil{return rest,err}
 candidate:=Objects{owner:owner}
`, string(declJSON), ar.Symbol, *ar.MaxEntries, *ar.Flags, *ar.MapExtra)
	for _, m := range ordinary {
		fmt.Fprintf(&b, `candidate.%s,err=owner.Map(%q)
 if err!=nil{return rest,errors.Join(err,owner.Close())}
`, exported(m.Symbol), m.Symbol)
	}
	b.WriteString(` *o=candidate
 return rest,nil
}
func(o *Objects) Close() error { if o==nil{return nil};return o.owner.Close() }
func(o *Objects) ReadArenaAt(dst []byte,off uint64)error {if o==nil{return arena.ErrArenaClosed};return o.owner.ReadArenaAt(dst,off)}
func(o *Objects) WriteArenaAt(src []byte,off uint64)error {if o==nil{return arena.ErrArenaClosed};return o.owner.WriteArenaAt(src,off)}
func(o *Objects) TestProgram(name string,in []byte)(uint32,[]byte,error){if o==nil{return 0,nil,arena.ErrArenaClosed};return o.owner.TestProgram(name,in)}
func(o *Objects) RunProgram(name string)(uint32,error){if o==nil{return 0,arena.ErrArenaClosed};return o.owner.RunProgram(name)}
`)
	// Keep imports used when a schema has neither records nor ordinary maps.
	b.WriteString("var _ = errors.Join\n")
	code, err := format.Source(b.Bytes())
	if err != nil {
		return nil, fmt.Errorf("owned bindings formatting: %w", err)
	}
	return code, nil
}
