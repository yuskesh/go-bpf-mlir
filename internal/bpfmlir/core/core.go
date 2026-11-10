// Package core resolves CO-RE relocations offline with cilium/ebpf's own
// btf.CORERelocate, accepting fixture or vmlinux target BTF. Error-free
// relocation alone does not prove compatibility: missing fields produce poison
// fixups that Apply accepts (inspect Access.Poisoned), and integer width/sign
// require the independent CheckKFields check. See docs/requirements_format.md.
package core

import (
	"encoding/binary"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/btfexact"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// Access describes an instruction before and after its CO-RE relocation.
type Access struct {
	Insn       int    // Instruction index; ld_imm64 counts as one, following cilium/ebpf.
	LocalField string // Local BTF field at the original offset.
	LocalOff   int16
	Poisoned   bool   // Missing target field poisoned the instruction.
	LoadBytes  int    // Relocated LDX read width (1/2/4/8), otherwise zero.
	Offset     int16  // Relocated offset.
	Relo       string // cilium/ebpf relocation description for diagnostics.
}

// Relocate applies program prog's CO-RE relocations against target BTF.
// structName identifies the local type used to recover original field names.
func Relocate(elfPath, prog, structName string, target *btf.Spec) ([]Access, error) {
	spec, err := ebpf.LoadCollectionSpec(elfPath)
	if err != nil {
		return nil, err
	}
	ps := spec.Programs[prog]
	if ps == nil {
		return nil, fmt.Errorf("%s: no program %q", elfPath, prog)
	}
	if spec.Types == nil {
		return nil, fmt.Errorf("%s: no BTF", elfPath)
	}
	insns := make(asm.Instructions, len(ps.Instructions))
	copy(insns, ps.Instructions)

	var relos []*btf.CORERelocation
	var at []int
	for i := range insns {
		if r := btf.CORERelocationMetadata(&insns[i]); r != nil {
			relos = append(relos, r)
			at = append(at, i)
		}
	}
	if len(relos) == 0 {
		return nil, nil // ELF without CO-RE need not contain the local BTF type.
	}
	local, err := localFields(spec.Types, structName)
	if err != nil {
		return nil, err
	}
	fixups, err := btf.CORERelocate(relos, []*btf.Spec{target}, binary.LittleEndian, spec.Types.TypeID)
	if err != nil {
		return nil, err
	}
	var out []Access
	for k, i := range at {
		before := insns[i]
		a := Access{Insn: i, LocalOff: before.Offset, LocalField: local[before.Offset], Relo: relos[k].String()}
		if err := fixups[k].Apply(&insns[i]); err != nil {
			return nil, fmt.Errorf("insn %d: %w", i, err)
		}
		after := insns[i]
		switch {
		case after.IsBuiltinCall() && after.Constant == btf.COREBadRelocationSentinel,
			after.OpCode.IsDWordLoad() && after.Constant == btf.COREBadRelocationSentinel:
			a.Poisoned = true
		case after.OpCode.Class() == asm.LdXClass:
			a.LoadBytes = after.OpCode.Size().Sizeof()
			a.Offset = after.Offset
		default:
			a.Offset = after.Offset
		}
		out = append(out, a)
	}
	return out, nil
}

// localFields maps local member byte offsets to names.
func localFields(types *btf.Spec, name string) (map[int16]string, error) {
	var st *btf.Struct
	if err := types.TypeByName(name, &st); err != nil {
		return nil, fmt.Errorf("local type %s: %w", name, err)
	}
	m := map[int16]string{}
	for _, mb := range st.Members {
		m[int16(mb.Offset.Bytes())] = mb.Name
	}
	return m, nil
}

// TargetFields maps target member names to byte offsets for fixture checks.
func TargetFields(target *btf.Spec, name string) (map[string]int, error) {
	var st *btf.Struct
	if err := btfexact.TypeByName(target, name, &st); err != nil {
		return nil, err
	}
	m := map[string]int{}
	for _, mb := range st.Members {
		m[mb.Name] = int(mb.Offset.Bytes())
	}
	return m, nil
}

// CheckKFields independently checks requirements against target BTF: struct
// and field presence, non-bitfield integer kind, width and sign. CO-RE
// relocation alone does not check the latter two. Empty means a match.
func CheckKFields(kf []requirements.KField, target *btf.Spec) []string {
	var out []string
	for _, k := range kf {
		where := fmt.Sprintf("program %s reads %s.%s as %s", k.Program, k.Struct, k.Field, k.Type)
		var st *btf.Struct
		if err := btfexact.TypeByName(target, k.Struct, &st); err != nil {
			out = append(out, fmt.Sprintf("%s: the target has no struct %s (%v)", where, k.Struct, err))
			continue
		}
		var mb *btf.Member
		twice := false
		path := strings.Split(k.Field, ".")
		for i, part := range path {
			var seen bool
			mb, seen = findMember(st, part)
			twice = twice || seen
			if mb == nil {
				break
			}
			if i+1 < len(path) {
				next, ok := btf.UnderlyingType(mb.Type).(*btf.Struct)
				if !ok {
					mb = nil
					break
				}
				st = next
			}
		}
		if mb == nil {
			msg := fmt.Sprintf("%s: the target struct %s has no field %s", where, k.Struct, k.Field)
			if twice {
				msg += " (the member search met the same anonymous type twice — nested in a cycle or shared)"
			}
			out = append(out, msg)
			continue
		}
		if name, ok := strings.CutPrefix(k.Type, "struct:"); ok {
			nested, isStruct := btf.UnderlyingType(mb.Type).(*btf.Struct)
			if !isStruct || nested.Name != name || mb.BitfieldSize != 0 {
				out = append(out, fmt.Sprintf("%s: the target field is %s, not embedded struct %s", where, mb.Type, name))
			}
			continue
		}
		// strptr requires a pointer to a one-byte integer after unwrapping
		// const, volatile and typedef qualifiers.
		if k.Type == requirements.KFieldStrPtr {
			p, isPtr := btf.UnderlyingType(mb.Type).(*btf.Pointer)
			if !isPtr {
				out = append(out, fmt.Sprintf("%s: the target field is %s, not a pointer", where, mb.Type))
				continue
			}
			if it, isInt := btf.UnderlyingType(p.Target).(*btf.Int); !isInt || it.Size != 1 {
				out = append(out, fmt.Sprintf("%s: the target field points to %s, not a 1-byte integer (char)", where, p.Target))
			}
			continue
		}
		// ptr:void requires a pointer to VOID after unwrapping const,
		// volatile and typedef (void *, const void *); void ** is not.
		if k.Type == requirements.KFieldPtrVoid {
			p, isPtr := btf.UnderlyingType(mb.Type).(*btf.Pointer)
			if !isPtr {
				out = append(out, fmt.Sprintf("%s: the target field is %s, not a pointer", where, mb.Type))
				continue
			}
			if _, isVoid := btf.UnderlyingType(p.Target).(*btf.Void); !isVoid {
				out = append(out, fmt.Sprintf("%s: the target field points to %s, not void", where, p.Target))
			}
			continue
		}
		// ptr:<T> requires a pointer to STRUCT T.
		if t, ok := strings.CutPrefix(k.Type, "ptr:"); ok {
			p, isPtr := btf.UnderlyingType(mb.Type).(*btf.Pointer)
			if !isPtr {
				out = append(out, fmt.Sprintf("%s: the target field is %s, not a pointer", where, mb.Type))
				continue
			}
			st, isStruct := btf.UnderlyingType(p.Target).(*btf.Struct)
			if !isStruct || st.Name != t {
				out = append(out, fmt.Sprintf("%s: the target field points to %s, not struct %s", where, p.Target, t))
			}
			continue
		}
		// [N]i8/[N]u8 requires exactly N one-byte integer elements; cilium
		// relocation does not independently check array length.
		if strings.HasPrefix(k.Type, "[") {
			n, _ := strconv.Atoi(k.Type[1:strings.Index(k.Type, "]")])
			arr, isArr := btf.UnderlyingType(mb.Type).(*btf.Array)
			if !isArr {
				out = append(out, fmt.Sprintf("%s: the target field is %s, not an array", where, mb.Type))
				continue
			}
			el, isInt := btf.UnderlyingType(arr.Type).(*btf.Int)
			if !isInt || el.Size != 1 {
				out = append(out, fmt.Sprintf("%s: the target array's element is %s, not a 1-byte integer", where, arr.Type))
				continue
			}
			if int(arr.Nelems) != n {
				out = append(out, fmt.Sprintf("%s: the target array has %d elements", where, arr.Nelems))
			}
			continue
		}
		if mb.BitfieldSize != 0 {
			out = append(out, fmt.Sprintf("%s: the target field is a bitfield (%d bits)", where, mb.BitfieldSize))
			continue
		}
		// enum:<bits> requires a target ENUM (cilium folds ENUM64 into
		// *btf.Enum of size 8) of bits/8 bytes. The sign is not a contract.
		// Bitfields were rejected above: a partial field is not a full-width read.
		if bits := requirements.KFieldEnumBits(k.Type); bits != 0 {
			en, isEnum := btf.UnderlyingType(mb.Type).(*btf.Enum)
			if !isEnum {
				out = append(out, fmt.Sprintf("%s: the target field is %s, not an enum", where, mb.Type))
				continue
			}
			if int(en.Size)*8 != bits {
				out = append(out, fmt.Sprintf("%s: the target field is a %d-bit enum (%s)", where, en.Size*8, en.Name))
			}
			continue
		}
		it, ok := btf.UnderlyingType(mb.Type).(*btf.Int)
		if !ok {
			out = append(out, fmt.Sprintf("%s: the target field is %s, not an integer", where, mb.Type))
			continue
		}
		signed := it.Encoding&btf.Signed != 0
		got := fmt.Sprintf("%s%d", map[bool]string{true: "i", false: "u"}[signed], it.Size*8)
		if got != k.Type {
			out = append(out, fmt.Sprintf("%s: the target field is %s (%s)", where, got, it.Name))
		}
	}
	sort.Strings(out)
	return out
}

// HasField reports whether the dotted member path exists in st, walking it as
// CheckKFields does (anonymous members breadth-first, intermediate parts
// through a STRUCT after typedef / qualifiers). The btf_presence field
// guard asks only presence, not the field's type.
func HasField(st *btf.Struct, path string) bool {
	parts := strings.Split(path, ".")
	for i, part := range parts {
		mb, _ := findMember(st, part)
		if mb == nil {
			return false
		}
		if i+1 < len(parts) {
			next, ok := btf.UnderlyingType(mb.Type).(*btf.Struct)
			if !ok {
				return false
			}
			st = next
		}
	}
	return true
}

// findMember searches direct and anonymous struct/union members breadth-first,
// matching cilium's coreFindMember and verifier lookup. Direct-only lookup
// would falsely reject fields such as sk_buff.mark/protocol in anonymous unions.
func findMember(st *btf.Struct, name string) (*btf.Member, bool) {
	// Visit each anonymous composite once to terminate on cyclic/malformed
	// BTF. Repeated types have identical members, so the first breadth-first
	// match is unchanged. twice supports the no-match diagnostic.
	queue := [][]btf.Member{st.Members}
	seen := map[btf.Type]bool{st: true}
	twice := false
	for len(queue) > 0 {
		ms := queue[0]
		queue = queue[1:]
		for i := range ms {
			if ms[i].Name == name {
				return &ms[i], twice
			}
			if ms[i].Name != "" {
				continue
			}
			var members []btf.Member
			u := btf.UnderlyingType(ms[i].Type)
			switch t := u.(type) {
			case *btf.Struct:
				members = t.Members
			case *btf.Union:
				members = t.Members
			default:
				continue
			}
			if seen[u] {
				twice = true
				continue
			}
			seen[u] = true
			queue = append(queue, members)
		}
	}
	return nil, twice
}

// CheckTracepoint checks btf_trace_<name>'s void (*)(void *, args...) signature.
// Each requested prefix argument must be a pointer to its named struct or an
// integer of matching width/sign; '-' skips its type check. Programs may
// declare only the first len(args) arguments. Empty means a match.
func CheckTracepoint(target *btf.Spec, name string, args []string) []string {
	var td *btf.Typedef
	if err := btfexact.TypeByName(target, "btf_trace_"+name, &td); err != nil {
		return []string{fmt.Sprintf("tracepoint %s: the target has no btf_trace_%s (%v)", name, name, err)}
	}
	ptr, ok := td.Type.(*btf.Pointer)
	if !ok {
		return []string{fmt.Sprintf("tracepoint %s: btf_trace_%s is not a function pointer", name, name)}
	}
	fp, ok := ptr.Target.(*btf.FuncProto)
	if !ok {
		return []string{fmt.Sprintf("tracepoint %s: btf_trace_%s does not point to a function prototype", name, name)}
	}
	// The first void* is tracepoint data, preceding program-visible arguments.
	params := fp.Params
	if len(params) == 0 {
		return []string{fmt.Sprintf("tracepoint %s: the prototype has no parameters", name)}
	}
	params = params[1:]
	if len(args) > len(params) {
		return []string{fmt.Sprintf("tracepoint %s: the program declares %d arguments but the target passes %d", name, len(args), len(params))}
	}
	var out []string
	for i, want := range args {
		// '-' checks count only. Integer spellings require matching BTF width
		// and sign; bool is unsigned.
		if want == "-" {
			continue
		}
		if len(want) >= 2 && (want[0] == 'i' || want[0] == 'u') && isIntSpelling(want) {
			it, ok := btf.UnderlyingType(params[i].Type).(*btf.Int)
			if !ok {
				out = append(out, fmt.Sprintf("tracepoint %s: argument %d is %s, not an integer %s", name, i, params[i].Type, want))
				continue
			}
			got := fmt.Sprintf("%s%d", map[bool]string{true: "i", false: "u"}[it.Encoding&btf.Signed != 0], it.Size*8)
			if got != want {
				out = append(out, fmt.Sprintf("tracepoint %s: argument %d is %s (%s), not %s", name, i, got, it.Name, want))
			}
			continue
		}
		p, ok := btf.UnderlyingType(params[i].Type).(*btf.Pointer)
		if !ok {
			out = append(out, fmt.Sprintf("tracepoint %s: argument %d is %s, not a pointer to struct %s", name, i, params[i].Type, want))
			continue
		}
		st, ok := btf.UnderlyingType(p.Target).(*btf.Struct)
		if !ok || st.Name != want {
			out = append(out, fmt.Sprintf("tracepoint %s: argument %d points to %s, not struct %s", name, i, p.Target, want))
		}
	}
	return out
}

// BTFFeaturesOf returns sorted BTF kind names and func_global actually present
// in the ELF as parsed by cilium.
func BTFFeaturesOf(elfPath string) ([]string, error) {
	spec, err := btf.LoadSpec(elfPath)
	if err != nil {
		return nil, err
	}
	set := map[string]bool{}
	for t, err := range spec.All() {
		if err != nil {
			return nil, err
		}
		// cilium folds DECL_TAG into type/member/argument Tags rather than
		// enumerating it as a kind. Count tags wherever attached.
		if hasDeclTag(t) {
			set["decl_tag"] = true
		}
		switch v := t.(type) {
		case *btf.Void:
		case *btf.Int:
			set["int"] = true
		case *btf.Pointer:
			set["ptr"] = true
		case *btf.Const:
			set["const"] = true
		case *btf.Volatile:
			set["volatile"] = true
		case *btf.Restrict:
			set["restrict"] = true
		case *btf.Array:
			set["array"] = true
		case *btf.Struct:
			set["struct"] = true
		case *btf.Union:
			set["union"] = true
		case *btf.Enum:
			if v.Size > 4 {
				set["enum64"] = true
			} else {
				set["enum"] = true
			}
		case *btf.Fwd:
			set["fwd"] = true
		case *btf.Typedef:
			set["typedef"] = true
		case *btf.Func:
			set["func"] = true
			if v.Linkage == btf.GlobalFunc {
				set["func_global"] = true
			}

		case *btf.FuncProto:
			set["func_proto"] = true
		case *btf.Var:
			set["var"] = true
		case *btf.Datasec:
			set["datasec"] = true
		case *btf.Float:
			set["float"] = true
		case *btf.TypeTag:
			set["type_tag"] = true
		default:
			set[fmt.Sprintf("?%T", t)] = true
		}
	}
	var out []string
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out, nil
}

// CheckBTFFeatures compares the complete sets of declared and emitted BTF
// features. Empty means equality.
func CheckBTFFeatures(elfPath string, declared []string) ([]string, error) {
	got, err := BTFFeaturesOf(elfPath)
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, f := range declared {
		want[f] = true
	}
	have := map[string]bool{}
	var out []string
	for _, f := range got {
		have[f] = true
		if !want[f] {
			out = append(out, fmt.Sprintf("the .BTF uses %s but the requirements do not declare it", f))
		}
	}
	for _, f := range declared {
		if !have[f] {
			out = append(out, fmt.Sprintf("the requirements declare %s but the .BTF does not use it", f))
		}
	}
	return out, nil
}

// hasDeclTag includes tags on types, struct/union members and function arguments.
func hasDeclTag(t btf.Type) bool {
	members := func(ms []btf.Member) bool {
		for _, m := range ms {
			if len(m.Tags) > 0 {
				return true
			}
		}
		return false
	}
	switch v := t.(type) {
	case *btf.Struct:
		return len(v.Tags) > 0 || members(v.Members)
	case *btf.Union:
		return len(v.Tags) > 0 || members(v.Members)
	case *btf.Typedef:
		return len(v.Tags) > 0
	case *btf.Var:
		return len(v.Tags) > 0
	case *btf.Func:
		if len(v.Tags) > 0 {
			return true
		}
		for _, ts := range v.ParamTags {
			if len(ts) > 0 {
				return true
			}
		}
	}
	return false
}

// isIntSpelling recognizes tp_btf integer argument spellings used in requirements
// and schema args.
func isIntSpelling(s string) bool {
	switch s {
	case "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64":
		return true
	}
	return false
}
