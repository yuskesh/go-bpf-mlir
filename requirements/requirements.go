// Package requirements reads .ebpf_requirements from ELF and matches it with
// live or recorded capabilities using only the standard library.
// The compiler does not know kernel versions: required program, helper and map
// capabilities are recorded in ELF and checked here before loading.
package requirements

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// Section names the ELF requirements section.
const Section = ".ebpf_requirements"

// Program holds one program's requirements.
type Program struct {
	Symbol     string
	ProgType   string
	ProgTypeID int64
	Helpers    []Helper // Numeric order.
}

// Helper names a helper without bpf_ and its enum bpf_func_id value.
type Helper struct {
	Name string
	ID   int64
}

// Map describes one ELF map; Key/Value/MaxEntries/Flags were added in format 2.
type Map struct {
	Symbol  string
	MapType string
	ID      int64
	// Schema type spelling (u32, i64, [16]i8, record:<symbol> or '-' if absent); empty in format 1.
	Key, Value        string
	MaxEntries, Flags uint64
}

// KField describes a CO-RE kernel struct field. cilium/ebpf does not match INT
// width or signedness, so precheck separately verifies an ordinary target BTF
// member with the declared width and sign.
type KField struct {
	Program, Struct, Field string
	Type                   string // i8..u64, ptr:<struct>, ptr:void, struct:T, enum:<bits>, [N]i8/[N]u8 byte arrays, or strptr.
}

// KFieldStrPtr describes char* to a one-byte integer, read by kernel.read_str
// through probe_read_kernel_str. Its minimum format version is 15.
const KFieldStrPtr = "strptr"

// KFieldPtrVoid describes a void * field read by kaddr.read. Its
// minimum format version is PtrVoidKFieldMinVersion.
const KFieldPtrVoid = "ptr:void"

// PtrVoidKFieldMinVersion is the minimum format of the kfield ptr:void value
// (older readers took ptr:<struct> with any name, so ptr:void would
// have been read as a pointer to a struct named void).
const PtrVoidKFieldMinVersion = 25

// EnumKFieldMinVersion is the minimum format of kfield enum:<bits> values and
// the btf feature enum.
const EnumKFieldMinVersion = 22

// KFieldEnumBits returns the width of an enum:<bits> kfield type, or 0.
func KFieldEnumBits(t string) int {
	switch t {
	case "enum:8":
		return 8
	case "enum:16":
		return 16
	case "enum:32":
		return 32
	case "enum:64":
		return 64
	}
	return 0
}

// kfieldTypeMinVersion returns the value's minimum format version. strptr needs
// 15, enum:<bits> 22; other values retain the row kind's minimum, 3
// (requirements_format.md).
func kfieldTypeMinVersion(t string) int {
	if t == KFieldPtrVoid {
		return PtrVoidKFieldMinVersion
	}
	if KFieldEnumBits(t) != 0 {
		return EnumKFieldMinVersion
	}
	if strings.HasPrefix(t, "struct:") {
		return 17
	}
	if t == KFieldStrPtr {
		return 15
	}
	return 0
}

// Attach describes a target and its signature. tp_btf matches btf_trace_<Target>
// in target BTF; trace_fentry matches a kernel FUNC without argument rows.
type Attach struct {
	Program    string
	AttachType string   // trace_raw_tp / trace_fentry / trace_fexit
	Target     string   // Tracepoint name.
	Args       []string // Kernel struct names for arguments.
	// fexit retsig describes target argument count and integer return type.
	// RetNargs < 0 means absent.
	RetNargs int
	RetType  string
	// fexit funcret: integer return type matched without nargs; "" means
	// absent. An fexit attach carries exactly one of retsig and funcret.
	FuncRet string `json:",omitempty"` // omitempty: Attach is serialized into the kfunc_loads key (keys of older recordings stay byte-identical).
	// a sleepable fentry (section fentry.s/<fn>, BPF_F_SLEEPABLE); the sleepable row follows the attach row.
	Sleepable bool `json:",omitempty"` // omitempty: Attach is serialized into cache keys (keys of older recordings stay byte-identical).
	// kprobe architecture, fixed-offset pt_regs fields (matched against target
	// BTF), and argument types matched against target FUNC_PROTO.
	Arch       string
	CtxFields  []CtxField
	KprobeArgs []KprobeArg
	// uprobe binary SHA-256 and argument types matched against its DWARF; Target is a symbol.
	BinarySHA256 string
	UprobeArgs   []KprobeArg
	// fentry farg struct names per index, matched against FUNC_PROTO; '-' is unread.
	FArgs []string
	// Generic attachment without companions. TargetKind is an AttachTargetKinds
	// value and TargetValue is the target, or empty if absent.
	Generic                 bool
	TargetKind, TargetValue string
	// raw_tp_writable tpbuf companion must be physically adjacent; empty means absent.
	TPBufferType string
	// Companion-family rows: trace_tp tpfield in strictly increasing offset order;
	// freplace extret (ExtNargs < 0 means absent) and extarg; trace_struct_ops
	// structop (struct/member), sharing RetNargs/RetType/FArgs for retsig/farg.
	TPFields                       []TPField
	ExtNargs                       int
	ExtRet                         string
	ExtArgs                        []string
	StructOpStruct, StructOpMember string
	// Multi-probe target count from attach and mtarget names in index order.
	// Loaders attach in that order and supply cookie i.
	MultiN   int
	MTargets []string
	// USDT semaphore declaration (required/none; empty means no row) and usdtarg
	// size/sign in strictly increasing n order. Target is provider:name.
	USDTSem  string
	USDTArgs []KprobeArg
	// ksyscall sysarg types in strictly increasing n order; Target is syscall name.
	// Multi-probe mtargetarg is strictly ordered by (i,n), exclusive with
	// shared KprobeArgs/UprobeArgs.
	SysArgs     []KprobeArg
	MTargetArgs []MTargetArg
}

// InnerMap is innermap <outer> <map type name> <enum> <key> <value> <max_entries>
// <flags>, immediately following an array_of_maps/hash_of_maps row. It defines
// the inner-map template enforced by the kernel, with map-row type spellings.
type InnerMap struct {
	Outer             string // Outer-map symbol.
	MapType           string
	ID                int64
	Key, Value        string
	MaxEntries, Flags uint64
}

// TPField describes a tracepoint field's declared offset, size and type spelling.
type TPField struct {
	Field         string
	Offset, Bytes int
	Sign          string // i (signed) / u
}

// CtxField describes a fixed-offset context struct field read:
// ctxfield <program> <struct> <field> <offset> <size>.
type CtxField struct {
	Struct, Field string
	Offset, Size  int
}

// KprobeArg is kprobearg <program> <n> <i|u><bits>|ptr. The one-based argument
// is read as that integer type; ptr reads the raw pointer as an eight-byte value.
type KprobeArg struct {
	N    int
	Type string
}

// Requirements holds the entire section.
type Requirements struct {
	Version       int
	SchemaSHA256  string // Schema file SHA-256, added in format 2; empty in format 1.
	Programs      []Program
	HelperTargets []HelperTarget `json:",omitempty"` // Target-specific dependencies; absent preserves older public JSON.
	Maps          []Map
	KFields       []KField      // Format 3.
	Attaches      []Attach      // Format 4.
	BTFFeatures   []string      // ELF .BTF kinds and func_global in name order, added in format 5.
	ArgTags       []ArgTag      // Verifier argument-tag dependencies, added in format 6.
	TailSlots     []TailSlot    // Loader-populated prog_array slots, separate from reachability; format 7.
	CtxAccesses   []CtxAccess   // Context field reads/writes, added in format 9.
	InnerMaps     []InnerMap    // Inner-map templates in outer-map row order, added in format 12.
	Kfuncs        []Kfunc       // Called kfunc signatures in row order, added in format 13.
	EnumVals      []EnumVal     // Kernel enum constants in row order, added in format 20.
	CoreEnums     []CoreEnum    // CO-RE enum value relocations in row order, added in format 26.
	KStructSizes  []KStructSize // Embedded kernel struct sizes, ascending, added in format 28.
	FibFlags      []FibFlag     // bpf_fib_lookup flag masks, added in format 21.
	DataKptrs     []string      // .data.<name> sections of hidden kptr globals, added in format 23.
	Arenas        []string      // Arena map symbols in name order, added in format 29.
	KsymVars      []KsymVar     // Typed ksym VARs in name order, added in format 24.
	Kconfigs      []Kconfig     // CONFIG_* externs in name order, added in format 24.
	Guards        []Guard       // Existence guards numbered 0, 1, …, added in format 24.
	// KFieldGuards maps a KFields index to its guarded list (format 24);
	// rows without the suffix are absent.
	KFieldGuards map[int][]int
	guardedLines []guardedRow // Guarded-capable rows in document order for the end-of-document binding checks.
	// Map-field usage is derived by FromELF, not a section row. Parse alone
	// leaves the three-state result at not_derived.
	MapFields MapFields
	// Actual ELF initial profile and private Program/Attach snapshots from derivation.
	kfuncProfiles map[string]kfuncProfileSnapshot
}

// TailSlot is tailslot <map> <slot> <program>. After loading and checking all
// ELF programs, loaders populate only declared slots. Map must be a prog_array
// row and program must be in the same ELF.
type TailSlot struct {
	Map     string
	Slot    uint32
	Program string
}

// CtxAccess is ctxaccess <program> <attach type|-> <struct> <field> <r|w> <bytes>.
// Query ctx_access before loading because accepted widths/fields vary by kernel.
type CtxAccess struct {
	Program, AttachType, Struct, Field, Mode string
	Bytes                                    int
}

// ArgTag records dependence on verifier handling of a reachable global
// subprogram's pointer argument tag. The compiler emits arg:nonnull with class
// mem (generic integer/struct data pointer). This capability is distinct from
// accepting BTF DECL_TAG itself.
type ArgTag struct {
	Program, Tag, Class string
}

// Parse reads section contents and rejects malformed input instead of silently returning no requirements.
func Parse(data []byte) (*Requirements, error) {
	sc := bufio.NewScanner(bytes.NewReader(data))
	r := &Requirements{}
	// Accept formats 1..MaxFormatVersion per docs/requirements_format.md.
	// ParseError records line, row kind and rule; conformance wants compare rules.
	if !sc.Scan() {
		return nil, perr(1, "", RuleHeader, "%s: empty", Section)
	}
	for v := 1; v <= MaxFormatVersion; v++ {
		if sc.Text() == fmt.Sprintf("ebpf-requirements %d", v) {
			r.Version = v
		}
	}
	if r.Version == 0 {
		return nil, perr(1, "", RuleHeader, "%s: unknown header %q (want \"ebpf-requirements 1\" .. \"%d\")", Section, sc.Text(), MaxFormatVersion)
	}
	// Program name -> r.Programs index. Never keep pointers to slice elements:
	// append can reallocate, leaving helper updates on the abandoned array.
	byName := map[string]int{}
	lastMap := ""         // Symbol only when the immediately preceding row is map; innermap binds positionally.
	lastPhysicalRow := "" // tpbuf binds physically after attach, not merely to the most recent attach.
	n := 1
	for sc.Scan() {
		n++
		f := strings.Split(sc.Text(), "\t")
		previousPhysicalRow := lastPhysicalRow
		lastPhysicalRow = f[0]
		rk, known := rowKind(f[0])
		// a trailing "guarded <g> …" after the row's own fields. Only
		// ksymvar and kfield carry it (format 24); on any other kind it is
		// guard_kind.
		var guarded []string
		hasGuarded := false
		if known && !(f[0] == "map" && r.Version < 2) && len(f) > rk.Fields && f[rk.Fields] == guardedWord {
			guarded, f, hasGuarded = f[rk.Fields+1:], f[:rk.Fields], true
			if !GuardedRows[f[0]] && r.Version >= rk.MinVersion { // A row below its own minimum stays min_version (checked below).
				return nil, perr(n, f[0], RuleGuardKind, "%s line %d: only ksymvar and kfield rows can be guarded, got %q", Section, n, sc.Text())
			}
			if r.Version < KsymVarMinVersion {
				return nil, perr(n, f[0], RuleMinVersion, "%s line %d: the guarded suffix needs version %d", Section, n, KsymVarMinVersion)
			}
		}
		// RowKinds owns field counts. Format-1 map has four; unknown rows provisionally
		// use four fields and are rejected below.
		want := 4
		if known && !(f[0] == "map" && r.Version < 2) {
			want = rk.Fields
		}
		// Variable-width rows (kfunc: 4..9) require Fields through RowMaxFields.
		if mx, variadic := RowMaxFields[f[0]]; known && variadic && len(f) >= want && len(f) <= mx {
			want = len(f)
		}
		if len(f) != want {
			if !known {
				return nil, perr(n, "", RuleUnknownKind, "%s line %d: want %d tab-separated fields, got %q", Section, n, want, sc.Text())
			}
			return nil, perr(n, f[0], RuleFields, "%s line %d: want %d tab-separated fields, got %q", Section, n, want, sc.Text())
		}
		if !known {
			return nil, perr(n, "", RuleUnknownKind, "%s line %d: unknown row kind %q", Section, n, f[0])
		}
		// Check each row's minimum format at its own position, including companions.
		if r.Version < rk.MinVersion {
			if f[0] == "schema" {
				return nil, perr(n, f[0], RuleMinVersion, "%s line %d: bad schema row %q", Section, n, sc.Text())
			}
			return nil, perr(n, f[0], RuleMinVersion, "%s line %d: %s rows need version %d", Section, n, f[0], rk.MinVersion)
		}
		// Check that multi-probe mtarget count reached N before leaving companions,
		// and that format-12 of_maps rows are immediately followed by innermap.
		afterMap := lastMap
		lastMap = ""
		if err := r.checkMultiAndInnerMapPending(n, f[0], afterMap); err != nil {
			return nil, err
		}
		if f[0] == "tpbuf" {
			if err := r.parseTPBuffer(n, f, sc.Text(), previousPhysicalRow == "attach", byName); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "sysarg" || f[0] == "mtargetarg" {
			if err := r.parseKfuncAndSyscallCompanion(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "kfunc" {
			if err := r.parseKfunc(n, f, sc.Text(), byName); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "helper_target" {
			if err := r.parseHelperTarget(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "kstructsize" {
			if err := r.parseKStructSize(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "coreenum" {
			if err := r.parseCoreEnum(n, f, sc.Text(), byName); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "enumval" {
			if err := r.parseEnumVal(n, f, sc.Text(), byName); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "fibflags" {
			if err := r.parseFibFlags(n, f, sc.Text(), byName); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "datakptr" {
			if err := r.parseDataKptr(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "arena" {
			if err := r.parseArena(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		// typed ksym VARs, CONFIG_* externs and existence guards.
		switch f[0] {
		case "ksymvar":
			if err := r.parseKsymVar(n, f, guarded, hasGuarded, sc.Text()); err != nil {
				return nil, err
			}
			continue
		case "kconfig":
			if err := r.parseKconfig(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		case "guard":
			if err := r.parseGuard(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "mtarget" || f[0] == "usdtsem" || f[0] == "usdtarg" {
			if err := r.parseMultiAndInnerMapCompanion(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "innermap" {
			if err := r.parseInnerMap(n, f, sc.Text(), afterMap); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "schema" {
			if r.SchemaSHA256 != "" {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: bad schema row %q", Section, n, sc.Text())
			}
			if f[1] != "sha256" || len(f[2]) != 64 {
				return nil, perr(n, f[0], RuleValue, "%s line %d: bad schema row %q", Section, n, sc.Text())
			}
			r.SchemaSHA256 = f[2]
			continue
		}
		if f[0] == "btf" {
			if _, err := BTFFeatureBlob(f[1]); err != nil {
				return nil, perr(n, f[0], RuleValue, "%s line %d: unknown BTF feature %q", Section, n, f[1])
			}
			// Feature values have their own minimum formats; type_tag requires 13.
			if mv := btfFeatureMinVersion(f[1]); r.Version < mv {
				return nil, perr(n, f[0], RuleMinVersion, "%s line %d: BTF feature %q needs version %d", Section, n, f[1], mv)
			}
			r.BTFFeatures = append(r.BTFFeatures, f[1])
			continue
		}
		if f[0] == "tailslot" {
			if _, ok := byName[f[3]]; !ok {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: tailslot for unknown program %q", Section, n, f[3])
			}
			var mp *Map
			for i := range r.Maps {
				if r.Maps[i].Symbol == f[1] {
					mp = &r.Maps[i]
				}
			}
			if mp == nil {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: tailslot for %q, which is not a prog_array map row", Section, n, f[1])
			}
			if mp.MapType != "prog_array" {
				return nil, perr(n, f[0], RuleValue, "%s line %d: tailslot for %q, which is not a prog_array map row", Section, n, f[1])
			}
			slot, err := strconv.ParseUint(f[2], 10, 32)
			if err != nil || slot >= mp.MaxEntries {
				return nil, perr(n, f[0], RuleValue, "%s line %d: bad slot %q for %q (max_entries %d)", Section, n, f[2], f[1], mp.MaxEntries)
			}
			for _, t := range r.TailSlots {
				if t.Map == f[1] && t.Slot == uint32(slot) {
					return nil, perr(n, f[0], RuleValue, "%s line %d: slot %d of %q appears twice", Section, n, slot, f[1])
				}
			}
			r.TailSlots = append(r.TailSlots, TailSlot{f[1], uint32(slot), f[3]})
			continue
		}
		if f[0] == "argtag" {
			if _, ok := byName[f[1]]; !ok {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: argtag for unknown program %q", Section, n, f[1])
			}
			if f[2] != "arg:nonnull" || f[3] != "mem" {
				return nil, perr(n, f[0], RuleValue, "%s line %d: unknown argtag %q %q (known: arg:nonnull mem)", Section, n, f[2], f[3])
			}
			r.ArgTags = append(r.ArgTags, ArgTag{Program: f[1], Tag: f[2], Class: f[3]})
			continue
		}
		// kprobe arch/ctxfield/kprobearg bind positionally to the preceding attach.
		// trace_perf permits only arch, establishing fixed bpf_perf_event_data offsets.
		if f[0] == "arch" && len(r.Attaches) > 0 && r.Attaches[len(r.Attaches)-1].AttachType == "trace_perf" {
			a := &r.Attaches[len(r.Attaches)-1]
			if a.Program != f[1] || a.Arch != "" {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], sc.Text())
			}
			if f[2] == "" {
				return nil, perr(n, f[0], RuleValue, "%s line %d: bad arch row %q", Section, n, sc.Text())
			}
			a.Arch = f[2]
			continue
		}
		if f[0] == "arch" || f[0] == "ctxfield" || f[0] == "kprobearg" || f[0] == "binary" || f[0] == "uprobearg" {
			k := len(r.Attaches) - 1
			probe := k >= 0 && isProbeAttach(r.Attaches[k].AttachType)
			// binary/uprobearg belong to uprobes; kprobearg belongs to kprobes.
			// Return probes have arch/ctxfield and, for uretprobe, binary, but no args.
			// Multi families retain those companions; USDT also accepts binary.
			if k < 0 || r.Attaches[k].Program != f[1] || !probe ||
				(f[0] == "binary" && !isUprobeFamily(r.Attaches[k].AttachType)) ||
				(f[0] == "uprobearg" && r.Attaches[k].AttachType != "uprobe" && r.Attaches[k].AttachType != "uprobe_multi") ||
				(f[0] == "kprobearg" && r.Attaches[k].AttachType != "kprobe" && r.Attaches[k].AttachType != "kprobe_multi") {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], sc.Text())
			}
			a := &r.Attaches[k]
			// Companion order: arch -> ctxfield -> (kprobearg | binary -> uprobearg),
			// with strictly increasing argument indices. Multi mtarget rows follow
			// arch/ctxfield/binary and must reach N before args. USDT uses binary ->
			// usdtsem -> usdtarg. ksyscall uses arch -> ctxfield -> sysarg.
			// mtargetarg is exclusive with shared kprobearg/uprobearg.
			beforeMultiAndSyscallRows := len(a.MTargets) == 0 && a.USDTSem == "" && len(a.USDTArgs) == 0 && len(a.SysArgs) == 0
			mtComplete := (!isMultiAttachType(a.AttachType) || len(a.MTargets) == a.MultiN) && len(a.MTargetArgs) == 0
			var inOrder bool
			switch f[0] {
			case "arch":
				inOrder = len(a.CtxFields) == 0 && len(a.KprobeArgs) == 0 && a.BinarySHA256 == "" && len(a.UprobeArgs) == 0 && beforeMultiAndSyscallRows
			case "ctxfield":
				inOrder = a.Arch != "" && len(a.KprobeArgs) == 0 && a.BinarySHA256 == "" && len(a.UprobeArgs) == 0 && beforeMultiAndSyscallRows
			case "binary":
				inOrder = a.Arch != "" && len(a.UprobeArgs) == 0 && beforeMultiAndSyscallRows
			case "kprobearg":
				inOrder = a.Arch != "" && mtComplete
			case "uprobearg":
				inOrder = a.BinarySHA256 != "" && mtComplete
			}
			if !inOrder {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], sc.Text())
			}
			switch f[0] {
			case "binary":
				if a.BinarySHA256 != "" {
					return nil, perr(n, f[0], RuleOrder, "%s line %d: bad binary row %q", Section, n, sc.Text())
				}
				if f[2] != "sha256" || len(f[3]) != 64 {
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad binary row %q", Section, n, sc.Text())
				}
				a.BinarySHA256 = f[3]
			case "uprobearg":
				na, err := strconv.Atoi(f[2])
				if err != nil || na < 1 || (!validIntSpelling(f[3]) && f[3] != "strptr" && f[3] != "ptr") {
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad uprobearg row %q", Section, n, sc.Text())
				}
				if f[3] == "ptr" && r.Version < 18 {
					return nil, perr(n, f[0], RuleMinVersion, "%s line %d: uprobearg type ptr needs version 18", Section, n)
				}
				if l := len(a.UprobeArgs); l > 0 && na <= a.UprobeArgs[l-1].N {
					return nil, perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], sc.Text())
				}
				a.UprobeArgs = append(a.UprobeArgs, KprobeArg{na, f[3]})
			case "arch":
				if a.Arch != "" {
					return nil, perr(n, f[0], RuleOrder, "%s line %d: bad arch row %q", Section, n, sc.Text())
				}
				if f[2] == "" {
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad arch row %q", Section, n, sc.Text())
				}
				a.Arch = f[2]
			case "ctxfield":
				off, err1 := strconv.Atoi(f[4])
				size, err2 := strconv.Atoi(f[5])
				if err1 != nil || err2 != nil || off < 0 || size <= 0 || f[2] == "" || f[3] == "" {
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad ctxfield row %q", Section, n, sc.Text())
				}
				a.CtxFields = append(a.CtxFields, CtxField{f[2], f[3], off, size})
			default:
				na, err := strconv.Atoi(f[2])
				// ptr reads a raw eight-byte pointer without dereferencing; match pointer type.
				if err != nil || na < 1 || !(validIntSpelling(f[3]) || f[3] == "ptr") {
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad kprobearg row %q", Section, n, sc.Text())
				}
				if l := len(a.KprobeArgs); l > 0 && na <= a.KprobeArgs[l-1].N {
					return nil, perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], sc.Text())
				}
				a.KprobeArgs = append(a.KprobeArgs, KprobeArg{na, f[3]})
			}
			continue
		}
		// farg binds to the preceding attach with contiguous zero-based indices.
		// fentry uses struct names; fmod_ret uses integer types or '-' after retsig.
		// lsm accepts the union of those types. struct_ops uses the same domain
		// after structop and optional retsig.
		if f[0] == "farg" {
			k := len(r.Attaches) - 1
			idx, err := strconv.Atoi(f[2])
			fmod := k >= 0 && r.Attaches[k].AttachType == "trace_fmod_ret"
			lsm := k >= 0 && (r.Attaches[k].AttachType == "trace_lsm" || r.Attaches[k].AttachType == "trace_lsm_cgroup") // trace_lsm_cgroup shares the same value domain.
			sops := k >= 0 && r.Attaches[k].AttachType == "trace_struct_ops"
			if k < 0 || r.Attaches[k].Program != f[1] || !(r.Attaches[k].AttachType == "trace_fentry" || fmod || lsm || sops) || (fmod && r.Attaches[k].RetNargs < 0) ||
				(sops && r.Attaches[k].StructOpStruct == "") {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: farg row out of order or malformed %q", Section, n, sc.Text())
			}
			if err != nil || f[3] == "" || (fmod && f[3] != "-" && !validIntSpelling(f[3])) {
				return nil, perr(n, f[0], RuleValue, "%s line %d: farg row out of order or malformed %q", Section, n, sc.Text())
			}
			// struct_ops enum arguments are enum:<bits> from format 19. The
			// ':' keeps them apart from struct names (C identifiers), so an older
			// object's farg such as enum32 stays a struct name.
			if strings.HasPrefix(f[3], EnumArgPrefix) {
				if !sops || !validEnumArgSpelling(f[3]) {
					return nil, perr(n, f[0], RuleValue, "%s line %d: farg enum type must be enum:8, enum:16, enum:32 or enum:64 after trace_struct_ops, got %q", Section, n, f[3])
				}
				if r.Version < EnumArgMinVersion {
					return nil, perr(n, f[0], RuleMinVersion, "%s line %d: farg type %q needs version %d", Section, n, f[3], EnumArgMinVersion)
				}
			}
			if idx != len(r.Attaches[k].FArgs) {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: farg row out of order or malformed %q", Section, n, sc.Text())
			}
			r.Attaches[k].FArgs = append(r.Attaches[k].FArgs, f[3])
			continue
		}
		// Exactly one retsig per fexit or fmod_ret attach records nargs and integer return type.
		if f[0] == "retsig" {
			k := len(r.Attaches) - 1
			// struct_ops retsig follows structop and precedes farg; void is also allowed.
			sops := k >= 0 && r.Attaches[k].AttachType == "trace_struct_ops"
			if k < 0 || r.Attaches[k].Program != f[1] || (r.Attaches[k].AttachType != "trace_fexit" && r.Attaches[k].AttachType != "trace_fmod_ret" && !sops) || r.Attaches[k].RetNargs >= 0 || r.Attaches[k].FuncRet != "" ||
				(sops && (r.Attaches[k].StructOpStruct == "" || len(r.Attaches[k].FArgs) > 0)) {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: retsig row out of order or malformed %q", Section, n, sc.Text())
			}
			na, err := strconv.Atoi(f[2])
			if err != nil || na < 0 || !(validIntSpelling(f[3]) || (sops && f[3] == "void")) {
				return nil, perr(n, f[0], RuleValue, "%s line %d: retsig row out of order or malformed %q", Section, n, sc.Text())
			}
			r.Attaches[k].RetNargs, r.Attaches[k].RetType = na, f[3]
			continue
		}
		// funcret <program> <i|u><bits> follows a trace_fexit attach once,
		// exclusive with retsig (the program reads the return value through
		// bpf_get_func_ret, so no nargs is baked into the ELF).
		if f[0] == "funcret" {
			k := len(r.Attaches) - 1
			if k < 0 || r.Attaches[k].Program != f[1] || r.Attaches[k].AttachType != "trace_fexit" || r.Attaches[k].RetNargs >= 0 || r.Attaches[k].FuncRet != "" {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: funcret row out of order or malformed %q", Section, n, sc.Text())
			}
			if !validIntSpelling(f[2]) {
				return nil, perr(n, f[0], RuleValue, "%s line %d: funcret type must be i8…u64, got %q", Section, n, f[2])
			}
			r.Attaches[k].FuncRet = f[2]
			continue
		}
		// sleepable <program> follows a trace_fentry attach once,
		// directly after it and before any farg row — the program is loaded with
		// BPF_F_SLEEPABLE (section fentry.s/<fn>). FromELF checks it against the
		// section name; Check asks the caps for the sleepable type pair.
		if f[0] == "sleepable" {
			k := len(r.Attaches) - 1
			if k < 0 || previousPhysicalRow != "attach" || r.Attaches[k].Program != f[1] || r.Attaches[k].AttachType != "trace_fentry" || r.Attaches[k].Sleepable || len(r.Attaches[k].FArgs) > 0 {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: sleepable row out of order or malformed %q (want one row directly after the program's trace_fentry attach row)", Section, n, sc.Text())
			}
			r.Attaches[k].Sleepable = true
			continue
		}
		// Companion-family rows bind positionally to the immediately preceding attachment.
		if f[0] == "tpfield" || f[0] == "extret" || f[0] == "extarg" || f[0] == "structop" {
			if err := r.parseTypedAttachCompanion(n, f, sc.Text()); err != nil {
				return nil, err
			}
			continue
		}
		if f[0] == "attach" || f[0] == "arg" {
			if _, ok := byName[f[1]]; !ok {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: %s for unknown program %q", Section, n, f[0], f[1])
			}
			if f[0] == "attach" {
				// Other known types use generic attachment rows: an ABI bpf_attach_type
				// or mechanism name and kind[:value] target, available since format 9.
				// Earlier unknown types retain the existing value-error behavior.
				generic := !knownAttachType(f[2])
				if r.Version < GenericAttachMinVersion {
					if generic { // Preserve the format-8-and-earlier value error for unknown attachment types.
						return nil, perr(n, f[0], RuleValue, "%s line %d: bad attach row %q", Section, n, sc.Text())
					}
					if !isLegacyAttachType(f[2]) {
						return nil, perr(n, f[0], RuleMinVersion, "%s line %d: attach type %q needs version %d", Section, n, f[2], attachTypeMinVersion(f[2]))
					}
				}
				// trace_fmod_ret requires format 10, as recorded by attachTypeMinVersion.
				if !generic && r.Version < attachTypeMinVersion(f[2]) {
					return nil, perr(n, f[0], RuleMinVersion, "%s line %d: attach type %q needs version %d", Section, n, f[2], attachTypeMinVersion(f[2]))
				}
				if generic {
					if !validAttachTypeName(f[2]) {
						return nil, perr(n, f[0], RuleValue, "%s line %d: bad attach row %q", Section, n, sc.Text())
					}
					kind, value, err := parseAttachTarget(f[3])
					if err != nil {
						return nil, perr(n, f[0], RuleValue, "%s line %d: bad attach target %q: %v", Section, n, f[3], err)
					}
					if kind == "map" && !r.hasMap(value) {
						return nil, perr(n, f[0], RuleOrder, "%s line %d: attach target map %q is not a map row", Section, n, value)
					}
					for _, a := range r.Attaches {
						if a.Program == f[1] {
							return nil, perr(n, f[0], RuleOrder, "%s line %d: program %q has a second attach row", Section, n, f[1])
						}
					}
					r.Attaches = append(r.Attaches, Attach{Program: f[1], AttachType: f[2], Target: f[3], RetNargs: -1, ExtNargs: -1, Generic: true, TargetKind: kind, TargetValue: value})
					continue
				}
				// Multi targets declare positive N, followed by N mtarget rows. USDT uses
				// provider:name, each a C identifier.
				multiN, multiOK := multiCount(f[3])
				if !isMultiAttachType(f[2]) {
					multiN = 0
				}
				if f[3] == "" || (f[2] == "tcx" && f[3] != "ingress" && f[3] != "egress") || (f[2] == "netkit" && !validNetkitDirection(f[3])) || (isTypedAttachType(f[2]) && !validTypedAttachTarget(f[2], f[3])) ||
					(isMultiAttachType(f[2]) && !multiOK) || (f[2] == "usdt" && !validUSDTTarget(f[3])) ||
					(isSyscallOrLSMCgroupAttachType(f[2]) && !validCName(f[3])) { // trace_lsm_cgroup targets hooks; ksyscall targets unprefixed syscall names.
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad attach row %q", Section, n, sc.Text())
				}
				// struct_ops target must reference an earlier map row in the same ELF.
				if f[2] == "trace_struct_ops" && !r.hasMap(f[3]) {
					return nil, perr(n, f[0], RuleOrder, "%s line %d: attach target map %q is not a map row", Section, n, f[3])
				}
				// One attach per program prevents positional companions binding ambiguously.
				for _, a := range r.Attaches {
					if a.Program == f[1] {
						return nil, perr(n, f[0], RuleOrder, "%s line %d: program %q has a second attach row", Section, n, f[1])
					}
				}
				r.Attaches = append(r.Attaches, Attach{Program: f[1], AttachType: f[2], Target: f[3], RetNargs: -1, ExtNargs: -1, MultiN: multiN})
				continue
			}
			k := len(r.Attaches) - 1
			idx, err := strconv.Atoi(f[2])
			if k < 0 || r.Attaches[k].Program != f[1] || r.Attaches[k].AttachType != "trace_raw_tp" {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: arg row out of order or malformed %q", Section, n, sc.Text())
			}
			if err != nil || f[3] == "" {
				return nil, perr(n, f[0], RuleValue, "%s line %d: arg row out of order or malformed %q", Section, n, sc.Text())
			}
			if idx != len(r.Attaches[k].Args) {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: arg row out of order or malformed %q", Section, n, sc.Text())
			}
			r.Attaches[k].Args = append(r.Attaches[k].Args, f[3])
			continue
		}
		// ctxaccess rows follow program order, then strictly increasing (struct,field,mode) without duplicates.
		if f[0] == "ctxaccess" {
			_, ok := byName[f[1]]
			if !ok {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: ctxaccess for unknown program %q", Section, n, f[1])
			}
			bytes, err := strconv.Atoi(f[6])
			if (f[2] != "-" && !validAttachTypeName(f[2])) || !validCName(f[3]) || !validCName(f[4]) || (f[5] != "r" && f[5] != "w") ||
				err != nil || (bytes != 1 && bytes != 2 && bytes != 4 && bytes != 8) {
				return nil, perr(n, f[0], RuleValue, "%s line %d: bad ctxaccess row %q", Section, n, sc.Text())
			}
			c := CtxAccess{f[1], f[2], f[3], f[4], f[5], bytes}
			// Name-bound rows check dependencies and uniqueness only; emitter owns order.
			// Each program/field/mode combination occurs once.
			for _, p := range r.CtxAccesses {
				if p.Program == c.Program && p.Struct == c.Struct && p.Field == c.Field && p.Mode == c.Mode {
					return nil, perr(n, f[0], RuleOrder, "%s line %d: ctxaccess row repeated %q", Section, n, sc.Text())
				}
			}
			r.CtxAccesses = append(r.CtxAccesses, c)
			continue
		}
		if f[0] == "kfield" {
			if strings.Contains(f[3], ".") || strings.HasPrefix(f[4], "struct:") {
				if r.Version < 17 {
					return nil, perr(n, f[0], RuleMinVersion, "kfield paths and struct types need version 17")
				}
				if !validKFieldPath(f[3]) || (strings.HasPrefix(f[4], "struct:") && !validKFieldIdentifier(strings.TrimPrefix(f[4], "struct:"))) {
					return nil, perr(n, f[0], RuleValue, "invalid embedded kfield path or struct name")
				}
			}
			if _, ok := byName[f[1]]; !ok {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: kfield for unknown program %q", Section, n, f[1])
			}
			if !kfieldTypes[f[4]] && !(strings.HasPrefix(f[4], "ptr:") && len(f[4]) > len("ptr:")) && !validKFieldByteArray(f[4]) && f[4] != KFieldStrPtr && !strings.HasPrefix(f[4], "struct:") && KFieldEnumBits(f[4]) == 0 {
				return nil, perr(n, f[0], RuleValue, "%s line %d: kfield type must be i8, u8, i16, u16, i32, u32, i64, u64, ptr:<struct>, ptr:void, [N]i8 / [N]u8 (N 1..64), strptr or enum:<8|16|32|64>, got %q", Section, n, f[4])
			}
			// strptr char* fields require format 15 and enum:<bits> format 22 under the value-specific minimum rule.
			if mv := kfieldTypeMinVersion(f[4]); r.Version < mv {
				return nil, perr(n, f[0], RuleMinVersion, "%s line %d: kfield type %q needs version %d", Section, n, f[4], mv)
			}
			r.KFields = append(r.KFields, KField{f[1], f[2], f[3], f[4]})
			if hasGuarded { // the guarded suffix (bound at the end of the document).
				gs, err := parseGuardedList(n, f[0], guarded, sc.Text())
				if err != nil {
					return nil, err
				}
				if r.KFieldGuards == nil {
					r.KFieldGuards = map[int][]int{}
				}
				r.KFieldGuards[len(r.KFields)-1] = gs
				r.guardedLines = append(r.guardedLines, guardedRow{line: n, ksym: -1, kfield: len(r.KFields) - 1})
			}
			continue
		}
		id, err := strconv.ParseInt(f[3], 10, 64)
		if err != nil {
			return nil, perr(n, f[0], RuleValue, "%s line %d: bad number %q", Section, n, f[3])
		}
		switch f[0] {
		case "program":
			if _, dup := byName[f[1]]; dup {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: program %q appears twice", Section, n, f[1])
			}
			r.Programs = append(r.Programs, Program{Symbol: f[1], ProgType: f[2], ProgTypeID: id})
			byName[f[1]] = len(r.Programs) - 1
		case "helper":
			i, ok := byName[f[1]]
			if !ok {
				return nil, perr(n, f[0], RuleOrder, "%s line %d: helper for unknown program %q", Section, n, f[1])
			}
			r.Programs[i].Helpers = append(r.Programs[i].Helpers, Helper{f[2], id})
		case "map":
			m := Map{Symbol: f[1], MapType: f[2], ID: id}
			if r.Version >= 2 {
				m.Key, m.Value = f[4], f[5]
				if m.MaxEntries, err = strconv.ParseUint(f[6], 10, 64); err != nil {
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad max_entries %q", Section, n, f[6])
				}
				if m.Flags, err = strconv.ParseUint(f[7], 10, 64); err != nil {
					return nil, perr(n, f[0], RuleValue, "%s line %d: bad flags %q", Section, n, f[7])
				}
			}
			r.Maps = append(r.Maps, m)
			lastMap = m.Symbol
		}
	}
	// At EOF (line zero), reject incomplete mtarget counts and missing innermap
	// after format-12 of_maps rows.
	if err := r.checkMultiAndInnerMapPending(0, "", lastMap); err != nil {
		return nil, err
	}
	// every arena map row has its arena row. Format 28 and
	// earlier documents keep reading without arena rows (no loader check).
	if err := r.checkArenaRows(); err != nil {
		return nil, err
	}
	if len(r.Programs) == 0 {
		return nil, perr(0, "", RuleDocument, "%s: no programs", Section)
	}
	if r.Version >= 2 && r.SchemaSHA256 == "" {
		return nil, perr(0, "", RuleDocument, "%s: version %d without a schema row", Section, r.Version)
	}
	if err := checkKFieldPrefixes(r.KFields); err != nil {
		return nil, perr(0, "kfield", RuleDocument, "%s", err)
	}
	// guarded lists and guard rows bind at the end (guard rows come last).
	if err := r.checkGuardBindings(); err != nil {
		return nil, err
	}
	return r, sc.Err()
}

// checkELFVersion checks all four bytes of e_version against EV_CURRENT (1).
// debug/elf checks only the low byte and would accept corrupt upper bytes;
// this matches the C loader's full-width check.
func checkELFVersion(r io.ReaderAt) error {
	var h [24]byte
	if _, err := r.ReadAt(h[:], 0); err != nil {
		return fmt.Errorf("ELF header: %w", err)
	}
	var v uint32
	switch h[5] { // EI_DATA
	case 1:
		v = binary.LittleEndian.Uint32(h[20:])
	case 2:
		v = binary.BigEndian.Uint32(h[20:])
	default:
		return nil // Leave the invalid endianness diagnostic to debug/elf.
	}
	if v != 1 {
		return fmt.Errorf("ELF e_version is %#x, want 1 (EV_CURRENT — all 4 bytes)", v)
	}
	return nil
}

// FromELF finds and parses the requirements section; missing sections fail explicitly.
func FromELF(r io.ReaderAt) (*Requirements, error) {
	if err := checkELFVersion(r); err != nil {
		return nil, err
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	s := f.Section(Section)
	if s == nil {
		return nil, fmt.Errorf("the object has no %s section (built by an older compiler?)", Section)
	}
	data, err := s.Data()
	if err != nil {
		return nil, err
	}
	req, err := Parse(data)
	if err != nil {
		return nil, err
	}
	// Derive map-field usage without failing section parsing. Record failed and
	// its reason; Check emits map_field_unknown for each record-valued map.
	if err := checkSleepableSections(f, req); err != nil {
		return nil, err
	}
	req.MapFields = deriveMapFields(r)
	req.kfuncProfiles = deriveKfuncProfiles(f, req)
	return req, nil
}

// HelperCalls independently scans ELF instructions for each FUNC's helper IDs.
// Instructions are eight bytes: call 0x85 with src_reg=0 names a helper in imm;
// src_reg=1 is a BPF pseudo-call and src_reg=2 is a kfunc, not a helper.
// ld_imm64 (0x18) spans sixteen bytes; function-address loads such as bpf_loop
// callbacks also create reachability edges.
// Results include helpers reachable transitively through pseudo-calls. With a
// relocation, target is symbol section at symbol value+(imm+1)*8; without one,
// it is current section at instruction position+(imm+1)*8. A target not at a
// FUNC start is an error, never silently omitted. loc is section index/offset.
type loc struct {
	sec int
	off uint64
}

// fn is one executable-section FUNC symbol returned by scanFuncs.
type fn struct {
	name        string
	sec         int
	start, size uint64
	helpers     map[int64]bool
	callees     []loc
	// Map OBJECT symbols referenced by ld_imm64. Unresolved maps populate mapErr:
	// HelperCalls ignores it, while map-field derivation fails.
	maps   []string
	mapErr error
	// kfunc names: src_reg=1 calls relocated to undefined symbols, not reachability edges.
	kfuncs []string
}

// scanFuncs is the instruction scan shared by HelperCalls and MapFieldUses.
func scanFuncs(f *elf.File) ([]*fn, map[loc]*fn, error) {
	syms, err := f.Symbols()
	if err != nil {
		return nil, nil, err
	}
	var fns []*fn
	byStart := map[loc]*fn{}
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || int(s.Section) >= len(f.Sections) || s.Section == elf.SHN_UNDEF {
			continue
		}
		if f.Sections[s.Section].Flags&elf.SHF_EXECINSTR == 0 {
			continue
		}
		x := &fn{name: s.Name, sec: int(s.Section), start: s.Value, size: s.Size, helpers: map[int64]bool{}}
		fns = append(fns, x)
		byStart[loc{x.sec, x.start}] = x
	}
	// SHT_REL relocations per section (Info selects target): instruction offset -> symbol.
	relocs := map[int]map[uint64]elf.Symbol{}
	for _, rs := range f.Sections {
		if rs.Type != elf.SHT_REL || int(rs.Info) >= len(f.Sections) {
			continue
		}
		data, err := rs.Data()
		if err != nil {
			return nil, nil, err
		}
		m := map[uint64]elf.Symbol{}
		for i := 0; i+16 <= len(data); i += 16 {
			off := binary.LittleEndian.Uint64(data[i:])
			info := binary.LittleEndian.Uint64(data[i+8:])
			idx := int(info >> 32)
			if idx == 0 || idx > len(syms) {
				return nil, nil, fmt.Errorf("relocation at %s+%#x names symbol %d outside the symbol table", f.Sections[rs.Info].Name, off, idx)
			}
			m[off] = syms[idx-1] // f.Symbols omits the empty symbol at index zero.
		}
		relocs[int(rs.Info)] = m
	}
	for _, x := range fns {
		data, err := f.Sections[x.sec].Data()
		if err != nil {
			return nil, nil, err
		}
		if x.start > uint64(len(data)) || x.size > uint64(len(data))-x.start {
			return nil, nil, fmt.Errorf("symbol %s runs past its section", x.name)
		}
		code := data[x.start : x.start+x.size]
		for i := 0; i+8 <= len(code); i += 8 {
			op, regs := code[i], code[i+1]
			if op == 0x18 {
				// Function-address loads, including bpf_loop callbacks, create reachability
				// edges to executable section symbols plus imm offsets, or FUNC symbols.
				// Omitting them loses callback helpers. Data/map symbols are not edges.
				at := x.start + uint64(i)
				recordMapRef(f, syms, x, relocs[x.sec], at, regs, code[i+4:i+8])
				if s, ok := relocs[x.sec][at]; ok && int(s.Section) < len(f.Sections) && s.Section != elf.SHN_UNDEF &&
					f.Sections[s.Section].Flags&elf.SHF_EXECINSTR != 0 {
					imm := uint64(binary.LittleEndian.Uint32(code[i+4 : i+8]))
					to := loc{int(s.Section), s.Value + imm}
					if byStart[to] == nil {
						return nil, nil, fmt.Errorf("%s: the function address loaded at +%#x does not point at the start of a function (section %d offset %#x)", x.name, i, to.sec, to.off)
					}
					x.callees = append(x.callees, to)
				}
				i += 8
				continue
			}
			if op != 0x85 {
				continue
			}
			imm := int64(int32(binary.LittleEndian.Uint32(code[i+4 : i+8])))
			switch regs >> 4 {
			case 0:
				x.helpers[imm] = true
			case 1:
				at := x.start + uint64(i)
				var to loc
				// kfunc calls have src_reg=1 and undefined .ksyms relocations. The loader
				// resolves kernel BTF IDs and rewrites src_reg=2. Record names only,
				// not helpers or BPF-to-BPF edges.
				if s, ok := relocs[x.sec][at]; ok && s.Section == elf.SHN_UNDEF {
					x.kfuncs = append(x.kfuncs, s.Name)
					continue
				}
				if s, ok := relocs[x.sec][at]; ok {
					to = loc{int(s.Section), uint64(int64(s.Value) + (imm+1)*8)}
				} else {
					to = loc{x.sec, uint64(int64(at) + (imm+1)*8)}
				}
				if byStart[to] == nil {
					return nil, nil, fmt.Errorf("%s: the BPF-to-BPF call at +%#x does not land on the start of a function (section %d offset %#x)", x.name, i, to.sec, to.off)
				}
				x.callees = append(x.callees, to)
			}
		}
	}
	return fns, byStart, nil
}

func HelperCalls(r io.ReaderAt) (map[string][]int64, error) {
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fns, byStart, err := scanFuncs(f)
	if err != nil {
		return nil, err
	}
	out := map[string][]int64{}
	for _, x := range fns {
		seen := map[int64]bool{}
		visited := map[*fn]bool{}
		var walk func(*fn)
		walk = func(g *fn) {
			if visited[g] {
				return
			}
			visited[g] = true
			for id := range g.helpers {
				seen[id] = true
			}
			for _, c := range g.callees {
				walk(byStart[c])
			}
		}
		walk(x)
		ids := []int64{}
		for id := range seen {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
		out[x.name] = ids
	}
	return out, nil
}

// CheckCalls compares declared and instruction-derived helper sets per program.
// It returns mismatch descriptions, empty on agreement.
func CheckCalls(req *Requirements, calls map[string][]int64) []string {
	var diffs []string
	for _, p := range req.Programs {
		want := map[int64]bool{}
		for _, h := range p.Helpers {
			want[h.ID] = true
		}
		got, ok := calls[p.Symbol]
		if !ok {
			diffs = append(diffs, fmt.Sprintf("program %s: no code for it in the object", p.Symbol))
			continue
		}
		have := map[int64]bool{}
		for _, id := range got {
			have[id] = true
			if !want[id] {
				diffs = append(diffs, fmt.Sprintf("program %s calls helper %d but its requirements do not list it", p.Symbol, id))
			}
		}
		for _, h := range p.Helpers {
			if !have[h.ID] {
				diffs = append(diffs, fmt.Sprintf("program %s lists helper %s (%d) but never calls it", p.Symbol, h.Name, h.ID))
			}
		}
	}
	return diffs
}

// Capabilities describes target kernel support, from recorded bpftool probes
// or live cilium/ebpf feature probes.
type Capabilities interface {
	HasProgType(name string, id int64) (bool, error)
	HasHelper(progType string, progTypeID int64, helper string, helperID int64) (bool, error)
	HasMapType(name string, id int64) (bool, error)
}

// Unmet describes one unsatisfied requirement. A Kind ending in _unknown means
// indeterminate rather than unsupported; some Unknown results block loading.
// UnmetKinds and docs/requirements_format.md define all kinds and load policy.
type Unmet struct {
	Kind    string // One of UnmetKinds.
	Program string // Program symbol for helper requirements.
	Name    string
	ID      int64
	Detail  string // Reason, such as kfield, attach or helper_unknown.
}

// Unknown distinguishes indeterminate support from established absence.
func (u Unmet) Unknown() bool { return strings.HasSuffix(u.Kind, "_unknown") }

// BlocksLoad implements load policy for unsupported and Unknown results.
// Unknown helpers may be decided by the verifier, but Unknown BTF support blocks:
// loader sanitization can silently rewrite BTF, invalidating load as evidence.
// Argument-tag semantics and fexit signatures also block when Unknown: wrong
// signatures can pass the verifier while producing incorrect values.
//
// kprobe architecture, fixed context offsets and argument types must be known
// before load/attach, since the kernel can accept a program that reads wrong
// values. Target-symbol and alias checks also block: cilium v0.22 link.Kprobe
// retries __x64_X after X returns ENOENT/EINVAL, potentially changing calling
// convention. Establish both X's presence and alias absence before loading.
//
// Unknown nullable-argument marking blocks: kernels without marking (6.6) can
// silently read nullable arguments as zero. Unknown CO-RE field and tracepoint
// argument types block too: cilium poisons absent fields but does not check
// integer widths, so load success alone cannot establish correct reads.
func (u Unmet) BlocksLoad() bool {
	if u.Kind == "helper_target_unknown" {
		return true
	}
	return !u.Unknown() || u.Kind == "btf_feature_unknown" || u.Kind == "kfield_unknown" || u.Kind == "attach_unknown" || u.Kind == "arg_nullable_mark_unknown" || u.Kind == "arg_tag_unknown" || u.Kind == "retsig_unknown" ||
		u.Kind == "arch_unknown" || u.Kind == "ctxfield_unknown" || u.Kind == "kprobearg_unknown" ||
		u.Kind == "attach_symbol_unknown" || u.Kind == "attach_alias_unknown" || u.Kind == "binary_unknown" || u.Kind == "uprobearg_unknown" ||
		u.Kind == "uprobearg_abi_unknown" || // Unknown target calling convention blocks.
		u.Kind == "uretprobe_abi_unknown" || // The same applies to uretprobe.
		u.Kind == "tpfield_unknown" || u.Kind == "ext_target_unknown" || u.Kind == "structop_unknown" || // These Unknown cases can silently read incorrect values.
		u.Kind == "farg_unknown" || // Unknown fentry argument types block to prevent reading the wrong struct.
		u.Kind == "usdtarg_unknown" || u.Kind == "usdt_loader_unknown" || // Unknown USDT argument locations or loader attachment strategy block.
		u.Kind == "kfunc_sig_unknown" || u.Kind == "sysarg_unknown" || u.Kind == "lsm_cgroup_loader_unknown" || u.Kind == "fsession_loader_unknown" || u.Kind == "ksyscall_loader_unknown" || // All these cases block under policy 12.
		u.Kind == "enumval_unknown" || // Policy 17: an unconfirmed enum value would silently change the program.
		u.Kind == "coreenum_unknown" || // Policy 21: an unconfirmed constant may be a poisoned instruction a guard hides from the verifier.
		u.Kind == "funcret_unknown" || // Policy 22: an unconfirmed return type passes the verifier and reads the value wrong.
		u.Kind == "kstructsize_unknown" || // Policy 23: an unconfirmed struct size may let a kfunc write past the embedded field.
		u.Kind == "fibflags_unknown" || // a rejected fib_lookup mask is only seen at run time.
		u.Kind == "datakptr_loader_unknown" || // an mmap of the kptr section fails the whole load (-ENOTSUPP).
		u.Kind == "arena_loader_unknown" || // a corrupted addr_space_cast or an unshared arena is unconfirmed.
		u.Kind == "typed_ksym_loader_unknown" || u.Kind == "ksymvar_unknown" || u.Kind == "kconfig_loader_unknown" || u.Kind == "kconfig_unknown" // an unresolved extern or an unconfirmed guard fails or silently changes the load.
}

// ErrUnknown indicates an indeterminate capability query, such as no probe.
// Implementations may wrap it; Check converts it to an Unknown Unmet rather
// than aborting with a query error.
var ErrUnknown = errors.New("cannot be determined on this target")

// BTFFeatureCaps optionally matches btf requirements. Without it,
// btf_feature_unknown blocks loading.
type BTFFeatureCaps interface {
	// HasBTFFeature tests whether the kernel accepts BTFFeatureBlob(f).
	HasBTFFeature(f string) (bool, error)
}

// ArgTagCaps checks verifier interpretation of argument tags, distinct from
// DECL_TAG acceptance: 6.6.157 accepts DECL_TAG but ignores arg: semantics.
// Probe with and without tags at fixed program type and pointer class; return
// ErrUnknown if the results do not establish the distinction.
type ArgTagCaps interface {
	HasArgTagSemantics(progType string, progTypeID int64, tag, class string) (bool, error)
}

// KernelTypes optionally matches tracepoint signatures and fields with target
// BTF. Missing support means Unknown; stdlib-only caps do not implement it.
type KernelTypes interface {
	// CheckTracepoint checks btf_trace_<name> and argument pointers to args[i]
	// structs. Return a mismatch description, or empty on agreement.
	CheckTracepoint(name string, args []string) ([]string, error)
	// CheckKFields checks presence, non-bitfield layout, width and sign; return mismatches as text.
	CheckKFields(kf []KField) ([]string, error)
}

// validIntSpelling recognizes retsig integer types i8/u8 through i64/u64.
// EnumArgPrefix starts a struct_ops enum farg value, enum:<bits>.
const EnumArgPrefix = "enum:"

// EnumArgMinVersion is the first format with struct_ops enum farg values.
const EnumArgMinVersion = 19

// validEnumArgSpelling recognizes enum:8 / enum:16 / enum:32 / enum:64.
func validEnumArgSpelling(s string) bool {
	switch s {
	case "enum:8", "enum:16", "enum:32", "enum:64":
		return true
	}
	return false
}

func validIntSpelling(s string) bool {
	switch s {
	case "i8", "u8", "i16", "u16", "i32", "u32", "i64", "u64":
		return true
	}
	return false
}

// KernelFuncSigs optionally matches BTF argument counts and integer returns.
// Without it, function-signature checking yields attach_func_unknown.
type KernelFuncSigs interface {
	// CheckFuncSig matches FUNC name's FUNC_PROTO nargs and integer ret, returning mismatch text.
	CheckFuncSig(name string, nargs int, ret string) ([]string, error)
}

// KernelFuncRets optionally matches a BTF FUNC's integer return type without
// the argument count (funcret rows of fexit programs reading the
// return value through bpf_get_func_ret). Missing support yields the blocking
// funcret_unknown.
type KernelFuncRets interface {
	// CheckFuncRet matches FUNC name's FUNC_PROTO integer ret, returning mismatch text.
	CheckFuncRet(name, ret string) ([]string, error)
}

// KernelFuncArgs optionally matches BTF struct-pointer arguments. Missing
// support yields farg_unknown and blocks load.
type KernelFuncArgs interface {
	// CheckFuncArgs matches zero-based arguments to args[i] struct pointers; '-'
	// skips matching. Return mismatch text or an ErrUnknown-wrapping error when
	// indeterminate, such as a missing target FUNC.
	CheckFuncArgs(name string, args []string) ([]string, error)
}

// KernelArch reports uname architecture for kprobe calling conventions.
// Missing support yields arch_unknown and blocks load.
type KernelArch interface {
	Arch() (string, error)
}

// KernelStructFields matches BTF offsets/sizes for fixed-offset context reads.
// Missing support yields ctxfield_unknown and blocks load.
type KernelStructFields interface {
	// CheckStructField checks member field in STRUCT st at offset with size bytes; return mismatch text.
	CheckStructField(st, field string, offset, size int) ([]string, error)
}

// KernelSymbols queries kallsyms. Missing or unreadable support yields
// attach_symbol_unknown, which blocks load.
type KernelSymbols interface {
	HasKernelSymbol(name string) (bool, error)
}

// KernelFuncParams matches target function argument types. Missing support or
// absent FUNC_PROTO yields kprobearg_unknown and blocks load.
type KernelFuncParams interface {
	// CheckFuncParam matches one-based parameter n to integer typ, returning
	// mismatch text. Missing/unreadable FUNC_PROTO returns a wrapped ErrUnknown.
	CheckFuncParam(name string, n int, typ string) ([]string, error)
}

// TracingHelperCaps queries Tracing helpers per trace_fentry/trace_fexit/
// trace_raw_tp attachment. Kernel tracing_prog_func_proto varies support by
// expected_attach_type (for example get_func_arg is absent for raw_tp).
// Missing support falls back to HasHelper; LiveCaps returns Unknown for Tracing
// there because cilium has no generic probe.
type TracingHelperCaps interface {
	HasTracingHelper(attachType, helper string, helperID int64) (bool, error)
}

// tracingAttach returns the Tracing companion family, or empty if none.
func tracingAttach(req *Requirements, prog string) string {
	for _, a := range req.Attaches {
		if a.Program == prog {
			switch a.AttachType {
			case "trace_fentry", "trace_fexit", "trace_raw_tp":
				return a.AttachType
			case "trace_iter": // Generic trace_iter iter:<target>.
				return "trace_iter"
			case "trace_fmod_ret", "modify_return": // trace_fmod_ret and generic modify_return func:<name> use ABI-name query keys.
				return "modify_return"
			}
		}
	}
	return ""
}

// NullableArgCaps checks PTR_MAYBE_NULL marking for nullable tp_btf arguments.
// Kernel 6.6 lacks raw_tp_null_args and silently reads null through PROBE_MEM
// as zero. Missing/indeterminate support yields arg_nullable_mark_unknown;
// absent marking yields arg_nullable. Both block load.
type NullableArgCaps interface {
	MarksNullableTPArgs() (bool, error)
}

// checkNullableArgs checks only trace_raw_tp attachments with struct-pointer
// argument rows, producing one Unmet per index. Unread '-' and integer arguments
// are never dereferenced and do not need nullable-pointer marking.
func checkNullableArgs(a Attach, caps Capabilities) ([]Unmet, error) {
	var ptrs []int
	for i, t := range a.Args {
		if t != "-" && !validIntSpelling(t) {
			ptrs = append(ptrs, i)
		}
	}
	if len(ptrs) == 0 {
		return nil, nil
	}
	// Keep Unmet Kind as string literals: spec tests inspect the source.
	var out []Unmet
	nc, ok := capsAs[NullableArgCaps](caps, QueryNullableArgs)
	if !ok {
		for _, i := range ptrs {
			out = append(out, Unmet{Kind: "arg_nullable_mark_unknown", Program: a.Program, Name: a.Target, ID: int64(i), Detail: "no nullable-argument probe"})
		}
		return out, nil
	}
	marks, err := nc.MarksNullableTPArgs()
	if errors.Is(err, ErrUnknown) {
		for _, i := range ptrs {
			out = append(out, Unmet{Kind: "arg_nullable_mark_unknown", Program: a.Program, Name: a.Target, ID: int64(i), Detail: err.Error()})
		}
		return out, nil
	}
	if err != nil {
		return nil, err
	}
	if !marks {
		for _, i := range ptrs {
			out = append(out, Unmet{Kind: "arg_nullable", Program: a.Program, Name: a.Target, ID: int64(i), Detail: "probe: an unchecked read of a NULL-able argument is accepted"})
		}
		return out, nil
	}
	// BTF does not encode nullability: raw_tp_null_args and __nullable argument
	// names determine it. On kernels that mark nullable arguments, an unchecked
	// dereference is rejected by the verifier at load.
	for _, i := range ptrs {
		out = append(out, Unmet{Kind: "arg_nullable_unknown", Program: a.Program, Name: a.Target, ID: int64(i)})
	}
	return out, nil
}

// TCXCaps checks BPF_TCX_INGRESS/EGRESS links. Missing/indeterminate support
// yields attach_tcx_unknown, which does not block load.
type TCXCaps interface {
	HasTCX() (bool, error)
}

// KernelFuncs checks target BTF functions; missing support yields attach_func_unknown.
type KernelFuncs interface {
	// CheckFunc returns mismatch text if FUNC name is absent, or empty when present.
	CheckFunc(name string) ([]string, error)
}

func (u Unmet) String() string {
	switch u.Kind {
	case "map_field":
		return fmt.Sprintf("program %s uses map %s whose value holds %s; the target's verifier rejects this map in this program type ( probe)", u.Program, u.Name, u.Detail)
	case "map_field_unknown":
		if u.Program == "" {
			return fmt.Sprintf("map %s has a record value; whether a program uses it with bpf_timer / bpf_spin_lock cannot be determined (Unknown — %s). Loading anyway: the verifier rejects a disallowed use loudly", u.Name, u.Detail)
		}
		return fmt.Sprintf("program %s uses map %s (%s); whether the target allows this cannot be determined (Unknown). Loading anyway: the verifier rejects a disallowed use loudly", u.Program, u.Name, u.Detail)
	case "helper":
		return fmt.Sprintf("program %s needs helper %s (%d), which the target does not offer to this program type", u.Program, u.Name, u.ID)
	case "program_type":
		return fmt.Sprintf("program %s needs program type %s (%d), which the target does not have", u.Program, u.Name, u.ID)
	case "attach":
		return fmt.Sprintf("program %s: %s", u.Program, u.Detail)
	case "kfield":
		return u.Detail // CheckKFields descriptions begin with the program name.
	case "arg_nullable_unknown":
		return fmt.Sprintf("program %s: whether %s argument %d may be NULL is not in the target BTF (Unknown — the kernel keeps it in an internal table; the verifier decides at load)", u.Program, u.Name, u.ID)
	case "arg_nullable":
		// State only the probe-established fact: no marking accepts unchecked reads.
		// Neither the resulting value nor the program's own checks were established.
		return fmt.Sprintf("program %s reads pointer argument %d of tracepoint %s; the target's verifier does not mark NULL-able tracepoint arguments (%s), so it does not enforce a NULL check before a read — not loading", u.Program, u.ID, u.Name, u.Detail)
	case "arg_nullable_mark_unknown":
		return fmt.Sprintf("program %s reads pointer argument %d of tracepoint %s; whether the target's verifier marks NULL-able tracepoint arguments cannot be determined (Unknown — %s). Not loading: the verifier might not enforce a NULL check before a read", u.Program, u.ID, u.Name, u.Detail)
	case "kfield_unknown":
		return fmt.Sprintf("program %s reads kernel field %s through CO-RE; this check cannot judge it (Unknown — it needs the target BTF). Not loading: the loader turns a missing field into a poisoned instruction and does not check the width or sign", u.Program, u.Name)
	case "farg":
		return u.Detail // CheckFuncArgs descriptions identify the function and mismatched argument.
	case "farg_unknown":
		return fmt.Sprintf("program %s reads the pointer arguments of kernel function %s through fentry; this check cannot judge their types (Unknown — it needs the target BTF). Not loading: an argument of another type is read as the declared struct silently", u.Program, u.Name)
	case "retsig_unknown":
		return fmt.Sprintf("program %s reads the return value of kernel function %s through fexit; this check cannot judge its signature (Unknown — it needs the target BTF). Not loading: a wrong signature passes the verifier and reads another argument as the return value", u.Program, u.Name)
	case "attach_tcx_unknown":
		return fmt.Sprintf("program %s attaches with tcx (%s); whether the target has tcx cannot be determined (Unknown — %s; the loader decides at attach)", u.Program, u.Name, u.Detail)
	case "sleepable_type":
		return fmt.Sprintf("program %s is loaded sleepable (fentry.s/%s) but the target kernel cannot load this program type / attach type pair sleepable (%s)", u.Program, u.Name, u.Detail)
	case "sleepable_type_unknown":
		return fmt.Sprintf("program %s is loaded sleepable (fentry.s/%s); whether the target kernel accepts a sleepable program of this type cannot be determined (Unknown — %s; the kernel refuses a bad load loudly)", u.Program, u.Name, u.Detail)
	case "attach_netkit_unknown":
		return fmt.Sprintf("program %s attaches with netkit (%s); whether the target has netkit cannot be determined (Unknown — %s; the loader decides at attach)", u.Program, u.Name, u.Detail)
	case "attach_func_unknown":
		return fmt.Sprintf("program %s attaches (fentry) to kernel function %s; this check cannot judge whether it exists (Unknown — it needs the target BTF; the loader and the kernel decide at attach)", u.Program, u.Name)
	case "attach_unknown":
		if u.Detail != "" {
			return fmt.Sprintf("program %s: %s (Unknown — Not loading: the tracepoint signature cannot be judged)", u.Program, u.Detail)
		}
		return fmt.Sprintf("program %s attaches to %s; this check cannot judge the tracepoint signature (Unknown — it needs the target BTF). Not loading: an argument of another type may pass the verifier", u.Program, u.Name)
	case "btf_feature":
		return fmt.Sprintf("the object's BTF uses %s, which the target kernel does not accept (load would fail or need the loader to rewrite the BTF)", u.Name)
	case "btf_feature_unknown":
		return fmt.Sprintf("the object's BTF uses %s; whether the target accepts it cannot be determined (Unknown — %s). Not loading: a loader could silently rewrite the BTF", u.Name, u.Detail)
	case "btf_rewrite":
		return fmt.Sprintf("the loader would rewrite the object's BTF on this target (%s) — not loading (no silent fallback)", u.Detail)
	case "arg_tag":
		return fmt.Sprintf("program %s relies on the verifier reading argument tag %s, which the target's verifier does not (the same object means something else there — not loading)", u.Program, u.Name)
	case "arg_tag_unknown":
		return fmt.Sprintf("program %s relies on the verifier reading argument tag %s; this cannot be determined (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "arch":
		return fmt.Sprintf("program %s: %s", u.Program, u.Detail)
	case "arch_unknown":
		return fmt.Sprintf("program %s reads pt_regs with the calling convention of %s; the target arch cannot be determined (Unknown — %s). Not loading: another arch reads other registers", u.Program, u.Name, u.Detail)
	case "ctxfield":
		return fmt.Sprintf("program %s: %s", u.Program, u.Detail)
	case "ctxfield_unknown":
		return fmt.Sprintf("program %s reads %s at a fixed offset; the target BTF cannot confirm it (Unknown — %s). Not loading: a moved field is read silently", u.Program, u.Name, u.Detail)
	case "attach_symbol_unknown":
		return fmt.Sprintf("program %s attaches (kprobe) to %s; whether the kernel symbol exists cannot be determined (Unknown — %s). Not loading: the loader may silently attach to another symbol", u.Program, u.Name, u.Detail)
	case "attach_alias":
		return fmt.Sprintf("program %s: %s", u.Program, u.Detail)
	case "attach_alias_unknown":
		return fmt.Sprintf("program %s attaches (kprobe) to %s; whether the loader's fallback alias exists cannot be determined (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "kprobearg":
		return fmt.Sprintf("program %s: %s", u.Program, u.Detail)
	case "kprobearg_unknown":
		return fmt.Sprintf("program %s reads argument %s as a typed value; the target BTF cannot confirm the function signature (Unknown — %s). Not loading: a changed signature passes load and attach and is read silently", u.Program, u.Name, u.Detail)
	case "binary", "uprobe_symbol", "uprobearg", "uprobe_debug_build_id", "uprobe_debug_crc":
		return fmt.Sprintf("program %s: %s", u.Program, u.Detail)
	case "binary_unknown":
		return fmt.Sprintf("program %s attaches (uprobe) to %s in a user binary; the binary was not given to this check (Unknown — %s). Not loading: its identity cannot be confirmed", u.Program, u.Name, u.Detail)
	case "uprobearg_unknown":
		return fmt.Sprintf("program %s reads argument %s as a typed value; the binary's DWARF cannot confirm it (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "uprobearg_abi":
		return fmt.Sprintf("program %s reads the arguments of %s with the SysV registers, which that function does not use: %s", u.Program, u.Name, u.Detail)
	case "uprobearg_abi_unknown":
		return fmt.Sprintf("program %s reads the arguments of %s with the SysV registers; the binary's DWARF cannot confirm the calling convention (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "uretprobe_abi":
		return fmt.Sprintf("program %s reads the return value of %s from the SysV return value register, which that function does not use alone: %s", u.Program, u.Name, u.Detail)
	case "uretprobe_abi_unknown":
		return fmt.Sprintf("program %s reads the return value of %s from the SysV return value register; the binary's DWARF cannot confirm the calling convention (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "helper_unknown":
		return fmt.Sprintf("program %s needs helper %s (%d); the target cannot be probed for it (Unknown — %s)", u.Program, u.Name, u.ID, u.Detail)
	case "attach_type":
		if SockmapLinkProgType(u.Detail) { // Loading can succeed while sockmap BPF_LINK_CREATE fails (no sockmap links in 6.6).
			return fmt.Sprintf("program %s (program type %s) loads with expected attach type %s, but the target kernel cannot create a BPF link of that attach type on a sockmap (the attach this object needs)", u.Program, u.Detail, u.Name)
		}
		if MultiLinkAttachType(u.Name) { // Loading can succeed while a multi-link fails without CONFIG_FPROBE.
			return fmt.Sprintf("program %s (program type %s) loads with expected attach type %s, but the target kernel cannot create a BPF link of that attach type (the attach this object needs)", u.Program, u.Detail, u.Name)
		}
		return fmt.Sprintf("program %s is loaded with expected attach type %s, which the target kernel does not accept for program type %s", u.Program, u.Name, u.Detail)
	case "attach_type_unknown":
		return fmt.Sprintf("program %s is loaded with expected attach type %s; whether the target accepts it cannot be determined (Unknown — %s). Loading anyway: the kernel rejects an unknown attach type loudly at load", u.Program, u.Name, u.Detail)
	case "attach_target":
		if strings.HasPrefix(u.Name, "map:") { // Map attachment targets resolve from ELF map rows; Detail names map-type mismatches.
			return fmt.Sprintf("program %s: %s", u.Program, u.Detail)
		}
		return fmt.Sprintf("program %s attaches (%s) to %s, which the target kernel does not have", u.Program, u.Detail, u.Name)
	case "attach_target_unknown":
		return fmt.Sprintf("program %s attaches to %s; whether the target has it cannot be determined (Unknown — %s). Loading anyway: the attach fails loudly if it is missing", u.Program, u.Name, u.Detail)
	case "ctx_access":
		return fmt.Sprintf("program %s accesses ctx field %s, which the target's verifier does not allow for %s", u.Program, u.Name, u.Detail)
	case "ctx_access_unknown":
		return fmt.Sprintf("program %s accesses ctx field %s; whether the target's verifier allows it cannot be determined (Unknown — %s). Loading anyway: the verifier rejects a disallowed access loudly", u.Program, u.Name, u.Detail)
	case "fibflags":
		return fmt.Sprintf("program %s calls bpf_fib_lookup with flags %s, which the target's helper rejects for %s. Not loading: the helper returns -EINVAL at run time and the verifier does not see it", u.Program, u.Name, u.Detail)
	case "datakptr_loader":
		return fmt.Sprintf("section %s holds hidden kptr globals; %s. Not loading: the kernel refuses mmap of a map with a kptr (-ENOTSUPP), failing the load", u.Name, u.Detail)
	case "datakptr_loader_unknown":
		return fmt.Sprintf("section %s holds hidden kptr globals; whether the loader mmaps them cannot be determined (Unknown — %s). Not loading: the kernel refuses mmap of a map with a kptr (-ENOTSUPP), failing the load", u.Name, u.Detail)
	case "arena_loader":
		return fmt.Sprintf("map %s is a BPF arena; %s. Not loading: the program's addr_space_cast must reach the kernel byte for byte, and the arena must be mmapped at its map_extra address to share it with userspace", u.Name, u.Detail)
	case "arena_loader_unknown":
		return fmt.Sprintf("map %s is a BPF arena; whether the loader keeps addr_space_cast intact and mmaps the arena at map_extra cannot be determined (Unknown — %s). Not loading", u.Name, u.Detail)
	case "typed_ksym_loader":
		return fmt.Sprintf("the object reads the per-CPU kernel variable %s through bpf_per_cpu_ptr; %s. Not loading: a kallsyms address is a scalar to the verifier, and bpf_per_cpu_ptr needs a BTF-typed pointer (ARG_PTR_TO_PERCPU_BTF_ID)", u.Name, u.Detail)
	case "typed_ksym_loader_unknown":
		return fmt.Sprintf("the object reads the per-CPU kernel variable %s; how the loader resolves a typed ksym cannot be determined (Unknown — %s). Not loading: without BPF_PSEUDO_BTF_ID the verifier rejects bpf_per_cpu_ptr", u.Name, u.Detail)
	case "ksymvar":
		return fmt.Sprintf("the object reads the per-CPU kernel variable %s; %s. Not loading: an unresolved strong extern fails the load, and a variable of another type is read as the declared slot", u.Name, u.Detail)
	case "ksymvar_unknown":
		return fmt.Sprintf("the object reads the per-CPU kernel variable %s; whether the target has it with the declared slot type cannot be determined (Unknown — %s). Not loading", u.Name, u.Detail)
	case "kconfig_loader":
		return fmt.Sprintf("the object reads %s; %s. Not loading: the loader refuses a weak .kconfig extern", u.Name, u.Detail)
	case "kconfig_loader_unknown":
		return fmt.Sprintf("the object reads %s; how the loader resolves CONFIG_* externs cannot be determined (Unknown — %s). Not loading", u.Name, u.Detail)
	case "kconfig":
		return fmt.Sprintf("the object reads %s, which the target's kconfig does not set (%s). Not loading: an unset strong extern fails the load", u.Name, u.Detail)
	case "kconfig_type":
		return fmt.Sprintf("the object reads %s, whose kconfig value does not fit the extern (%s). Not loading: the loader rejects the value", u.Name, u.Detail)
	case "kconfig_unknown":
		return fmt.Sprintf("the object reads %s; its kconfig value cannot be determined (Unknown — %s). Not loading: a loader that cannot read the kconfig file fails the load, and the value is never guessed", u.Name, u.Detail)
	case "fibflags_unknown":
		return fmt.Sprintf("program %s calls bpf_fib_lookup with flags %s; whether the target's helper accepts them cannot be determined (Unknown — %s). Not loading: a rejected mask is only seen at run time", u.Program, u.Name, u.Detail)
	case "tpfield":
		return fmt.Sprintf("program %s reads tracepoint field %s: %s", u.Program, u.Name, u.Detail)
	case "tpfield_unknown":
		return fmt.Sprintf("program %s reads tracepoint field %s at a fixed offset; the target's tracepoint format cannot confirm it (Unknown — %s). Not loading: a moved or resized field is read silently", u.Program, u.Name, u.Detail)
	case "ext_target":
		return fmt.Sprintf("program %s replaces function %s: %s", u.Program, u.Name, u.Detail)
	case "ext_target_unknown":
		return fmt.Sprintf("program %s replaces function %s; its signature cannot be confirmed (Unknown — %s). Not loading: the kernel compares neither the sign of the arguments nor the return value's width, and a mismatch is read silently", u.Program, u.Name, u.Detail)
	case "structop":
		return fmt.Sprintf("program %s implements struct_ops member %s: %s", u.Program, u.Name, u.Detail)
	case "structop_unknown":
		return fmt.Sprintf("program %s implements struct_ops member %s; the target BTF cannot confirm the member and its signature (Unknown — %s). Not loading: an argument of another type is read silently", u.Program, u.Name, u.Detail)
	case "map_type":
		if u.Detail == "inner" { // Inner-map template.
			return fmt.Sprintf("map %s holds inner maps of map type %s (%d), which the target does not have", u.Program, u.Name, u.ID)
		}
		return fmt.Sprintf("map %s needs map type %s (%d), which the target does not have", u.Program, u.Name, u.ID)
	case "usdt_probe":
		return fmt.Sprintf("program %s attaches (usdt) to %s: %s", u.Program, u.Name, u.Detail)
	case "usdtarg":
		return fmt.Sprintf("program %s reads USDT argument %s: %s", u.Program, u.Name, u.Detail)
	case "usdtarg_unknown":
		return fmt.Sprintf("program %s reads USDT argument %s; the point's argument cannot be read by this check (Unknown — %s). Not loading: an argument of another size or place is read silently", u.Program, u.Name, u.Detail)
	case "usdt_loader":
		return fmt.Sprintf("program %s attaches (usdt) to %s: %s — not loading", u.Program, u.Name, u.Detail)
	case "usdt_loader_unknown":
		return fmt.Sprintf("program %s attaches (usdt) to %s; how the loader attaches USDT points cannot be determined (Unknown — %s). Not loading: a loader that does not pass the semaphore's ref_ctr_offset leaves a guarded point silent", u.Program, u.Name, u.Detail)
	case "kfunc_sig":
		return fmt.Sprintf("program %s calls kfunc %s: %s", u.Program, u.Name, u.Detail)
	case "kfunc_sig_unknown":
		return fmt.Sprintf("program %s calls kfunc %s; its prototype cannot be confirmed (Unknown — %s). Not loading: an argument of another integer width or sign passes the verifier and is read silently", u.Program, u.Name, u.Detail)
	case "kfunc_allowed":
		return fmt.Sprintf("program %s calls kfunc %s, which the kernel rejects in its exact initial profile (%s). Not loading", u.Program, u.Name, u.Detail)
	case "kfunc_allowed_unknown":
		return fmt.Sprintf("program %s calls kfunc %s; its use in the exact initial profile cannot be confirmed (Unknown — %s). Loading anyway: the kernel rejects a disallowed kfunc loudly at load", u.Program, u.Name, u.Detail)
	case "sysarg":
		return fmt.Sprintf("program %s reads syscall argument %s: %s", u.Program, u.Name, u.Detail)
	case "sysarg_unknown":
		return fmt.Sprintf("program %s reads syscall argument %s; the target cannot confirm its type (Unknown — %s). Not loading: a wrong width, sign or pointer is read silently", u.Program, u.Name, u.Detail)
	case "lsm_cgroup_loader":
		return fmt.Sprintf("program %s attaches (lsm_cgroup) to %s: %s — not loading", u.Program, u.Name, u.Detail)
	case "lsm_cgroup_loader_unknown":
		return fmt.Sprintf("program %s attaches (lsm_cgroup) to %s; whether the loader can load an lsm_cgroup program cannot be determined (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "fsession_loader":
		return fmt.Sprintf("program %s attaches (fsession) to %s: %s — not loading", u.Program, u.Name, u.Detail)
	case "fsession_loader_unknown":
		return fmt.Sprintf("program %s attaches (fsession) to %s; whether the loader can load an fsession program cannot be determined (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "ksyscall_loader":
		return fmt.Sprintf("program %s attaches (ksyscall) to syscall %s: %s — not loading", u.Program, u.Name, u.Detail)
	case "ksyscall_loader_unknown":
		return fmt.Sprintf("program %s attaches (ksyscall) to syscall %s; where the loader attaches a ksyscall program cannot be determined (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "enumval":
		return fmt.Sprintf("program %s uses the enum constant %s: %s — not loading", u.Program, u.Name, u.Detail)
	case "enumval_unknown":
		return fmt.Sprintf("program %s uses the enum constant %s; its value on the target cannot be confirmed (Unknown — %s). Not loading: a different value silently changes what the program does", u.Program, u.Name, u.Detail)
	case "coreenum":
		return fmt.Sprintf("program %s reads the enum constant %s through a CO-RE relocation: %s — not loading (the loader would poison the instruction)", u.Program, u.Name, u.Detail)
	case "coreenum_unknown":
		return fmt.Sprintf("program %s reads the enum constant %s through a CO-RE relocation; whether the target has it cannot be determined (Unknown — %s). Not loading: an absent constant is a poisoned instruction", u.Program, u.Name, u.Detail)
	case "funcret":
		return fmt.Sprintf("program %s reads the return value of kernel function %s through fexit (bpf_get_func_ret): %s — not loading (a wrong width or sign passes the verifier and reads the value wrong)", u.Program, u.Name, u.Detail)
	case "funcret_unknown":
		return fmt.Sprintf("program %s reads the return value of kernel function %s through fexit (bpf_get_func_ret); this check cannot judge its return type (Unknown — %s). Not loading: a wrong width or sign passes the verifier and reads the value wrong", u.Program, u.Name, u.Detail)
	case "helper_target":
		return fmt.Sprintf("program %s calls helper %s at a typed target: %s — not loading", u.Program, u.Name, u.Detail)
	case "helper_target_unknown":
		return fmt.Sprintf("program %s calls helper %s at a typed target; acceptance cannot be determined (Unknown — %s). Not loading", u.Program, u.Name, u.Detail)
	case "kstructsize":
		return fmt.Sprintf("the object embeds struct %s (%s bytes): %s — not loading (a kfunc writes the target's struct size and would overwrite the bytes after the field)", kstructName(u.Name), kstructBytes(u.Name), u.Detail)
	case "kstructsize_unknown":
		return fmt.Sprintf("the object embeds struct %s (%s bytes); the target's struct size cannot be confirmed (Unknown — %s). Not loading: a larger struct would let a kfunc overwrite the bytes after the field", kstructName(u.Name), kstructBytes(u.Name), u.Detail)
	}
	// spec tests require cases above for all UnmetKinds; only unlisted kinds reach here.
	return fmt.Sprintf("unmet requirement %s: program %s, %s (%s)", u.Kind, u.Program, u.Name, u.Detail)
}

// Check matches requirements against capabilities and returns unmet ones.
// Query failures return errors, never silently imply support or absence.
func Check(req *Requirements, caps Capabilities) ([]Unmet, error) {
	out, targetErr := checkHelperTargets(req, caps)
	if targetErr != nil {
		return out, targetErr
	}
	for _, p := range req.Programs {
		ok, err := caps.HasProgType(p.ProgType, p.ProgTypeID)
		if err != nil {
			return nil, err
		}
		if !ok {
			out = append(out, Unmet{Kind: "program_type", Program: p.Symbol, Name: p.ProgType, ID: p.ProgTypeID})
			continue
		}
		// Tracing helper support varies by expected_attach_type. Use the attachment
		// and tracing_helpers query when available; otherwise retain HasHelper fallback.
		th, thOK := capsAs[TracingHelperCaps](caps, QueryTracingHelper)
		at := tracingAttach(req, p.Symbol)
		for _, h := range p.Helpers {
			if needsHelperTarget(p, h) {
				continue
			}
			var ok bool
			var err error
			if thOK && at != "" {
				ok, err = th.HasTracingHelper(at, h.Name, h.ID)
			} else {
				ok, err = caps.HasHelper(p.ProgType, p.ProgTypeID, h.Name, h.ID)
			}
			if errors.Is(err, ErrUnknown) {
				out = append(out, Unmet{Kind: "helper_unknown", Program: p.Symbol, Name: h.Name, ID: h.ID, Detail: err.Error()})
				continue
			}
			if err != nil {
				return nil, err
			}
			if !ok {
				out = append(out, Unmet{Kind: "helper", Program: p.Symbol, Name: h.Name, ID: h.ID})
			}
		}
	}
	// kfunc rows match target BTF FUNC_PROTO signatures.
	if len(req.Kfuncs) > 0 {
		u, err := checkKfuncs(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	// enumval rows match target BTF enum constant values.
	if len(req.EnumVals) > 0 {
		u, err := checkEnumVals(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	// coreenum rows check that the target BTF has the constant.
	if len(req.CoreEnums) > 0 {
		u, err := checkCoreEnums(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	// kstructsize rows check every embedded struct against the target's size.
	if len(req.KStructSizes) > 0 {
		u, err := checkKStructSizes(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	// CO-RE fields and tracepoint signatures need target BTF; missing KernelTypes
	// means Unknown, not success. Missing KernelFuncs also means Unknown for
	// fentry targets, but does not block: loader/attach failures are explicit.
	askedAttachType := map[string]bool{} // Query each (program, attach type) once across generic attach and ctxaccess.
	for _, a := range req.Attaches {
		// Generic attach rows carry attach_type (except mechanism names) and attach_target.
		if a.Generic {
			u, err := checkGenericAttach(req, a, caps, askedAttachType)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			out = append(out, checkProgLoader(a, caps)...) // lsm_cgroup/fsession loader declarations also apply to generic format-9 rows.
			u, err = checkTPBuffer(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		// trace_lsm_cgroup shares generic hook queries plus farg/loader checks.
		// ksyscall additionally checks wrapper, sysarg and loader declarations.
		if isSyscallOrLSMCgroupAttachType(a.AttachType) {
			u, err := checkSyscallAndLSMCgroup(req, a, caps, askedAttachType)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			out = append(out, checkProgLoader(a, caps)...)
			continue
		}
		if a.AttachType == "netkit" {
			u, err := checkNetkit(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		// Established missing TCX support blocks; Unknown does not, because attach fails explicitly.
		if a.AttachType == "tcx" {
			tc, ok := capsAs[TCXCaps](caps, QueryTCX)
			if !ok {
				out = append(out, Unmet{Kind: "attach_tcx_unknown", Program: a.Program, Name: a.Target, Detail: "no tcx probe"})
				continue
			}
			have, err := tc.HasTCX()
			if errors.Is(err, ErrUnknown) {
				out = append(out, Unmet{Kind: "attach_tcx_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()})
				continue
			}
			if err != nil {
				return nil, err
			}
			if !have {
				out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.Target,
					Detail: "the target kernel has no tcx attach (BPF_TCX_INGRESS / EGRESS links)"})
			}
			continue
		}
		// Match each multi-probe mtarget; USDT matches note points and loader declarations.
		if isMultiAttachType(a.AttachType) {
			u, err := checkMulti(req, a, caps, askedAttachType)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		if a.AttachType == "usdt" {
			u, err := checkUSDT(req, a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		if a.AttachType == "uprobe" || a.AttachType == "uretprobe" { // uretprobe shares binary/symbol matching, without argument rows.
			u, err := checkUprobe(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		if a.AttachType == "kprobe" || a.AttachType == "kretprobe" { // kretprobe shares these checks and cilium's alias retry behavior.
			u, err := checkKprobe(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		// Companion families share generic attach_type/attach_target checks, plus their companion rows.
		if isTypedAttachType(a.AttachType) {
			u, err := checkTypedAttach(req, a, caps, askedAttachType)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		// fmod_ret matches retsig like fexit, integer farg against FUNC_PROTO, and function presence.
		if a.AttachType == "trace_fmod_ret" {
			u, err := checkFmodRet(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
			continue
		}
		if a.AttachType != "trace_fentry" && a.AttachType != "trace_fexit" {
			continue
		}
		// fexit requires retsig; an attach without it is malformed ELF.
		if a.AttachType == "trace_fexit" {
			if a.FuncRet != "" {
				// the return value read through bpf_get_func_ret — no nargs.
				kr, ok := capsAs[KernelFuncRets](caps, QueryFuncRet)
				if !ok {
					// A wrong width or sign passes the verifier and reads the value wrong.
					out = append(out, Unmet{Kind: "funcret_unknown", Program: a.Program, Name: a.Target, Detail: "no function return type probe"})
					continue
				}
				diffs, err := kr.CheckFuncRet(a.Target, a.FuncRet)
				if errors.Is(err, ErrUnknown) {
					out = append(out, Unmet{Kind: "funcret_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()})
					continue
				}
				if err != nil {
					return nil, err
				}
				for _, d := range diffs {
					out = append(out, Unmet{Kind: "funcret", Program: a.Program, Name: a.Target, Detail: d})
				}
				continue
			}
			if a.RetNargs < 0 {
				return nil, fmt.Errorf("program %s: fexit attach row without a retsig or funcret row", a.Program)
			}
			ks, ok := capsAs[KernelFuncSigs](caps, QueryFuncSig)
			if !ok {
				// Wrong nargs may pass verification while reading another argument slot as
				// the return value. Thus retsig_unknown blocks, unlike Unknown fentry
				// function presence, where loader/attach failures are explicit.
				out = append(out, Unmet{Kind: "retsig_unknown", Program: a.Program, Name: a.Target})
				continue
			}
			diffs, err := ks.CheckFuncSig(a.Target, a.RetNargs, a.RetType)
			if err != nil {
				return nil, err
			}
			for _, d := range diffs {
				out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.Target, Detail: d})
			}
			continue
		}
		// a sleepable fentry asks the caps for the program type / attach type pair (a false answer
		// blocks, Unknown does not — the per-function allowlist is the kernel's to refuse loudly).
		if a.Sleepable {
			u, err := checkSleepable(a, programTypeOf(req, a.Program), caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
		}
		// Match fentry argument types only when farg rows are present.
		if len(a.FArgs) > 0 {
			u, err := checkFentryArgs(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
		}
		kf, ok := capsAs[KernelFuncs](caps, QueryFunc)
		if !ok {
			out = append(out, Unmet{Kind: "attach_func_unknown", Program: a.Program, Name: a.Target})
			continue
		}
		diffs, err := kf.CheckFunc(a.Target)
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.Target, Detail: d})
		}
	}
	// Tracepoint and field queries are independent; recorded caps may contain
	// only one, though live KernelTypes provides both.
	if kt, ok := capsAs[KernelTypes](caps, QueryTracepoint); ok {
		for _, a := range req.Attaches {
			if a.AttachType != "trace_raw_tp" {
				continue
			}
			diffs, err := kt.CheckTracepoint(a.Target, a.Args)
			if err != nil {
				return nil, err
			}
			for _, d := range diffs {
				out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.Target, Detail: d})
			}
			u, err := checkNullableArgs(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
		}
	} else {
		for _, a := range req.Attaches {
			if a.AttachType != "trace_raw_tp" {
				continue
			}
			out = append(out, Unmet{Kind: "attach_unknown", Program: a.Program, Name: a.Target})
			u, err := checkNullableArgs(a, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
		}
	}
	// guarded kfield rows are checked one by one after the others.
	plainKFields := req.KFields
	if len(req.KFieldGuards) > 0 {
		plainKFields = nil
		for i, k := range req.KFields {
			if _, g := req.KFieldGuards[i]; !g {
				plainKFields = append(plainKFields, k)
			}
		}
	}
	if kt, ok := capsAs[KernelTypes](caps, QueryKFields); ok {
		diffs, err := kt.CheckKFields(plainKFields)
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "kfield", Detail: d})
		}
	} else {
		for _, k := range plainKFields {
			out = append(out, Unmet{Kind: "kfield_unknown", Program: k.Program, Name: k.Struct + "." + k.Field + " (" + k.Type + ")"})
		}
	}
	if len(req.KFieldGuards) > 0 {
		u, err := checkKFieldsGuarded(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	// Unknown BTF features block loading. Loader rewriting depends on both
	// kernel support and the loader's declared handling of unsupported features.
	if bc, ok := capsAs[BTFFeatureCaps](caps, QueryBTFFeature); ok && len(req.BTFFeatures) > 0 {
		decl := loaderOf(caps)
		var rewrites, undeclared []string
		for _, f := range req.BTFFeatures {
			ok, err := bc.HasBTFFeature(f)
			switch {
			case err != nil:
				out = append(out, Unmet{Kind: "btf_feature_unknown", Name: f, Detail: err.Error()})
			case !ok:
				out = append(out, Unmet{Kind: "btf_feature", Name: f})
				if name, rewritable := btfRewriteNames[f]; rewritable {
					switch decl.BTFRewrite[f] {
					case BTFRewriteRewrite:
						rewrites = append(rewrites, name)
					case BTFRewriteKeep:
					default:
						undeclared = append(undeclared, f)
					}
				}
			}
		}
		if len(undeclared) > 0 {
			out = append(out, Unmet{Kind: "btf_feature_unknown", Name: "loader rewrites",
				Detail: fmt.Sprintf("loader %q does not declare what it does with %s on a kernel that lacks it", decl.Name, strings.Join(undeclared, ", "))})
		}
		if len(rewrites) > 0 {
			out = append(out, Unmet{Kind: "btf_rewrite", Detail: strings.Join(rewrites, ", ")})
		}
	} else {
		for _, f := range req.BTFFeatures {
			out = append(out, Unmet{Kind: "btf_feature_unknown", Name: f, Detail: "this checker cannot probe the target BTF"})
		}
	}
	// Unknown argument-tag semantics blocks: ignoring tags changes callee verification.
	if len(req.ArgTags) > 0 {
		progOf := map[string]Program{}
		for _, p := range req.Programs {
			progOf[p.Symbol] = p
		}
		ac, ok := capsAs[ArgTagCaps](caps, QueryArgTag)
		for _, a := range req.ArgTags {
			p := progOf[a.Program]
			name := a.Tag + " (" + a.Class + ")"
			if !ok {
				out = append(out, Unmet{Kind: "arg_tag_unknown", Program: a.Program, Name: name, Detail: "this checker cannot probe the verifier's reading of argument tags"})
				continue
			}
			has, err := ac.HasArgTagSemantics(p.ProgType, p.ProgTypeID, a.Tag, a.Class)
			switch {
			case err != nil:
				out = append(out, Unmet{Kind: "arg_tag_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			case !has:
				out = append(out, Unmet{Kind: "arg_tag", Program: a.Program, Name: name})
			}
		}
	}
	// Context access checks attach_type (unless '-') and ctx_access.
	if len(req.CtxAccesses) > 0 {
		u, err := checkCtxAccesses(req, caps, askedAttachType)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	// bpf_fib_lookup flag masks (false and Unknown block).
	if len(req.FibFlags) > 0 {
		u, err := checkFibFlags(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	// kptr data sections ask the loader declaration only (both block).
	out = append(out, checkDataKptrs(req, caps)...)
	// arena maps ask the loader declarations arena_cast / arena_premmap only (both block).
	out = append(out, checkArenas(req, caps)...)
	// typed ksym VARs and CONFIG_* externs (loader declaration, then kernel).
	if len(req.KsymVars) > 0 {
		u, err := checkKsymVars(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	if len(req.Kconfigs) > 0 {
		u, err := checkKconfigs(req, caps)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
	}
	for _, m := range req.Maps {
		ok, err := caps.HasMapType(m.MapType, m.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			out = append(out, Unmet{Kind: "map_type", Program: m.Symbol, Name: m.MapType, ID: m.ID})
		}
	}
	// Inner-map types follow outer-map rules: false yields map_type with Detail
	// inner; Unknown is a query error.
	for _, im := range req.InnerMaps {
		ok, err := caps.HasMapType(im.MapType, im.ID)
		if err != nil {
			return nil, err
		}
		if !ok {
			out = append(out, Unmet{Kind: "map_type", Program: im.Outer, Name: im.MapType, ID: im.ID, Detail: "inner"})
		}
	}
	// Match map-field policy by program type. Missing program types already block
	// through program_type, so skip them here.
	noType := map[string]bool{}
	for _, u := range out {
		if u.Kind == "program_type" {
			noType[u.Program] = true
		}
	}
	mf, err := checkMapFields(req, caps, noType)
	if err != nil {
		return nil, err
	}
	out = append(out, mf...)
	return out, nil
}

// CheckShared compares same-named map definitions across ELF requirements:
// type, key, value, max_entries and flags. Kernel checks only key/value sizes,
// so userspace must detect type mismatches. names parallels reqs for diagnostics.
// Return mismatch descriptions.
func CheckShared(names []string, reqs []*Requirements) []string {
	type seen struct {
		from string
		m    Map
	}
	first := map[string]seen{}
	var out []string
	for i, r := range reqs {
		if r.Version < 2 {
			out = append(out, fmt.Sprintf("%s: requirements v%d has no map definitions (rebuild it)", names[i], r.Version))
			continue
		}
		for _, m := range r.Maps {
			s, ok := first[m.Symbol]
			if !ok {
				first[m.Symbol] = seen{names[i], m}
				continue
			}
			if s.m != m {
				out = append(out, fmt.Sprintf("map %s: %s says %s key=%s value=%s max_entries=%d flags=%d, but %s says %s key=%s value=%s max_entries=%d flags=%d",
					m.Symbol, s.from, s.m.MapType, s.m.Key, s.m.Value, s.m.MaxEntries, s.m.Flags,
					names[i], m.MapType, m.Key, m.Value, m.MaxEntries, m.Flags))
			}
		}
	}
	// Also compare inner templates for shared outer-map names. Do not compare
	// pairs where one ELF predates innermap and therefore has no template.
	type seenInner struct {
		from string
		m    InnerMap
	}
	firstInner := map[string]seenInner{}
	for i, r := range reqs {
		for _, im := range r.InnerMaps {
			s, ok := firstInner[im.Outer]
			if !ok {
				firstInner[im.Outer] = seenInner{names[i], im}
				continue
			}
			if s.m != im {
				out = append(out, fmt.Sprintf("map %s: %s says inner %s, but %s says inner %s", im.Outer, s.from, InnerMapSpelling(s.m), names[i], InnerMapSpelling(im)))
			}
		}
	}
	return out
}

// KprobeFallbackPrefix returns Cilium022.KprobeAliasPrefix for compatibility,
// or empty for unknown architectures. Matching uses caps LoaderCaps instead.
func KprobeFallbackPrefix(arch string) string {
	return Cilium022.KprobeAliasPrefix[arch]
}

// checkKprobe matches architecture, fixed BTF context offsets, kallsyms target
// and FUNC_PROTO arguments. Unknown symbols or argument types block load.
func checkKprobe(a Attach, caps Capabilities) ([]Unmet, error) {
	out, targetArch, err := checkArchAndCtx(a, caps)
	if err != nil {
		return nil, err
	}
	return checkKprobeTarget(a, caps, out, targetArch, true)
}

// checkArchAndCtx shares architecture/context-offset checks for kprobe/uprobe.
// It also returns target architecture, empty when indeterminate.
func checkArchAndCtx(a Attach, caps Capabilities) ([]Unmet, string, error) {
	if a.Arch == "" {
		return nil, "", fmt.Errorf("program %s: %s attach row without an arch row", a.Program, a.AttachType)
	}
	var out []Unmet
	targetArch := "" // Loader fallback uses the loader target's architecture, not the ELF declaration.
	if ka, ok := capsAs[KernelArch](caps, QueryArch); !ok {
		out = append(out, Unmet{Kind: "arch_unknown", Program: a.Program, Name: a.Arch, Detail: "no arch probe"})
	} else if arch, err := ka.Arch(); errors.Is(err, ErrUnknown) {
		out = append(out, Unmet{Kind: "arch_unknown", Program: a.Program, Name: a.Arch, Detail: err.Error()})
	} else if err != nil {
		return nil, "", err
	} else if targetArch = arch; arch != a.Arch {
		out = append(out, Unmet{Kind: "arch", Program: a.Program, Name: a.Arch,
			Detail: fmt.Sprintf("the object reads pt_regs with the calling convention of %s, but the target is %s", a.Arch, arch)})
	}
	for _, c := range a.CtxFields {
		name := fmt.Sprintf("%s.%s (offset %d, %d bytes)", c.Struct, c.Field, c.Offset, c.Size)
		ks, ok := capsAs[KernelStructFields](caps, QueryStructField)
		if !ok {
			out = append(out, Unmet{Kind: "ctxfield_unknown", Program: a.Program, Name: name, Detail: "no BTF probe"})
			continue
		}
		diffs, err := ks.CheckStructField(c.Struct, c.Field, c.Offset, c.Size)
		if errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "ctxfield_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			continue
		}
		if err != nil {
			return nil, "", err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "ctxfield", Program: a.Program, Name: name, Detail: d})
		}
	}
	return out, targetArch, nil
}

// checkKprobeTarget matches kallsyms presence/aliases and FUNC_PROTO arguments.
// askAlias=false skips alias queries for multi-probes.
func checkKprobeTarget(a Attach, caps Capabilities, out []Unmet, targetArch string, askAlias bool) ([]Unmet, error) {
	// Require both X's presence and absence of the loader fallback <prefix>X.
	if sy, ok := capsAs[KernelSymbols](caps, QueryKernelSym); !ok {
		out = append(out, Unmet{Kind: "attach_symbol_unknown", Program: a.Program, Name: a.Target, Detail: "no kallsyms probe"})
	} else if found, err := sy.HasKernelSymbol(a.Target); errors.Is(err, ErrUnknown) {
		out = append(out, Unmet{Kind: "attach_symbol_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()})
	} else if err != nil {
		return nil, err
	} else {
		if !found {
			out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.Target,
				Detail: fmt.Sprintf("kprobe target %s is not a kernel symbol on the target (kallsyms)", a.Target)})
		}
		// Prefix comes from the loader declaration, defaulting to Cilium022.
		// Missing architecture means Unknown; empty prefix means no retry.
		// cilium/libbpf KprobeMulti never retries aliases and skips this query.
		alias, known := kprobeAlias(caps, targetArch)
		if !askAlias {
			// No-retry family: alias presence cannot change the result.
		} else if !known {
			out = append(out, Unmet{Kind: "attach_alias_unknown", Program: a.Program, Name: a.Target, Detail: "no fallback prefix known for the target arch " + strconv.Quote(targetArch)})
		} else if alias == "" {
			// No-retry loader: alias presence cannot change the result.
		} else if afound, err := sy.HasKernelSymbol(alias + a.Target); errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "attach_alias_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()})
		} else if err != nil {
			return nil, err
		} else if afound {
			out = append(out, Unmet{Kind: "attach_alias", Program: a.Program, Name: a.Target,
				Detail: fmt.Sprintf("the target also has %s%s; the loader (%s) retries with that syscall-wrapper name when attaching to %s fails, and would read another calling convention — not loading without an exact attach", alias, a.Target, loaderLabel(caps), a.Target)})
		}
	}
	for _, k := range a.KprobeArgs {
		name := fmt.Sprintf("%d of %s (%s)", k.N, a.Target, k.Type)
		fp, ok := capsAs[KernelFuncParams](caps, QueryFuncParam)
		if !ok {
			out = append(out, Unmet{Kind: "kprobearg_unknown", Program: a.Program, Name: name, Detail: "no BTF probe"})
			continue
		}
		diffs, err := fp.CheckFuncParam(a.Target, k.N, k.Type)
		if errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "kprobearg_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "kprobearg", Program: a.Program, Name: name, Detail: d})
		}
	}
	return out, nil
}

// kfieldTypes lists 8/16/32/64-bit integers. Extending this value domain did not
// raise the format: older readers reject unknown spellings with RuleValue.
var kfieldTypes = map[string]bool{"i8": true, "u8": true, "i16": true, "u16": true, "i32": true, "u32": true, "i64": true, "u64": true}

// validKFieldByteArray recognizes [N]i8/[N]u8 with N from 1 through 64.
func validKFieldByteArray(t string) bool {
	if !strings.HasPrefix(t, "[") || !(strings.HasSuffix(t, "]i8") || strings.HasSuffix(t, "]u8")) {
		return false
	}
	n, err := strconv.Atoi(t[1 : len(t)-3])
	return err == nil && n >= 1 && n <= 64 && t[1:len(t)-3] == strconv.Itoa(n)
}

// AttachTypeCaps checks program/expected_attach_type support. Missing or
// indeterminate support yields nonblocking attach_type_unknown, since kernel
// load rejection is explicit.
type AttachTypeCaps interface {
	HasAttachType(progType string, progTypeID int64, attachType string) (bool, error)
}

// AttachTargetCaps checks generic targets: functions, tracepoints, iterators,
// LSM hooks, user symbols, maps or programs. Missing/indeterminate support
// yields nonblocking attach_target_unknown, since attachment fails explicitly.
type AttachTargetCaps interface {
	HasAttachTarget(attachType, kind, value string) (bool, error)
}

// CtxAccessCaps checks context access by program and attachment type.
// Missing/indeterminate support yields nonblocking ctx_access_unknown: the
// verifier explicitly rejects invalid bpf_context access.
type CtxAccessCaps interface {
	AllowsCtxAccess(progType string, progTypeID int64, attachType, strct, field, mode string, bytes int) (bool, error)
}

func programOf(req *Requirements, sym string) (Program, bool) {
	for _, p := range req.Programs {
		if p.Symbol == sym {
			return p, true
		}
	}
	return Program{}, false
}

// checkAttachType queries each (program,attach type) once, skipping mechanism
// names and '-'. Keep Unmet Kind literals for source-inspecting spec tests.
func checkAttachType(req *Requirements, program, attachType string, caps Capabilities, asked map[string]bool) ([]Unmet, error) {
	if attachType == "-" || isAttachMechanism(attachType) || asked[program+"\x00"+attachType] {
		return nil, nil
	}
	asked[program+"\x00"+attachType] = true
	p, ok := programOf(req, program)
	if !ok {
		return nil, fmt.Errorf("attach type %s for unknown program %s", attachType, program)
	}
	ac, ok := capsAs[AttachTypeCaps](caps, QueryAttachType)
	if !ok {
		return append([]Unmet(nil), Unmet{Kind: "attach_type_unknown", Program: program, Name: attachType, Detail: "no attach type probe"}), nil
	}
	has, err := ac.HasAttachType(p.ProgType, p.ProgTypeID, attachType)
	switch {
	case errors.Is(err, ErrUnknown):
		return append([]Unmet(nil), Unmet{Kind: "attach_type_unknown", Program: program, Name: attachType, Detail: err.Error()}), nil
	case err != nil:
		return nil, err
	case !has:
		// A prog_attach sockmap loader needs no link. Suppress attach_type results
		// for sk_skb/sk_msg, including false: unsupported loading still fails
		// explicitly, as for attach_type_unknown.
		if SockmapLinkProgType(p.ProgType) && loaderOf(caps).SockmapAttach == SockmapAttachProgAttach {
			return nil, nil
		}
		return append([]Unmet(nil), Unmet{Kind: "attach_type", Program: program, Name: attachType, Detail: p.ProgType}), nil
	}
	return nil, nil
}

// checkGenericAttach checks attach_type and valued attach_target requirements.
func checkGenericAttach(req *Requirements, a Attach, caps Capabilities, asked map[string]bool) ([]Unmet, error) {
	out, err := checkAttachType(req, a.Program, a.AttachType, caps, asked)
	if err != nil {
		return nil, err
	}
	if a.TargetValue == "" {
		return out, nil
	}
	// Resolve sockmap/sockhash/struct_ops targets from this ELF's maps, not caps.
	if answered, mismatch := staticMapTarget(req, a); answered {
		if mismatch != "" {
			out = append(out, Unmet{Kind: "attach_target", Program: a.Program, Name: a.Target, Detail: mismatch})
		}
		return out, nil
	}
	tc, ok := capsAs[AttachTargetCaps](caps, QueryAttachTarget)
	if !ok {
		return append(out, Unmet{Kind: "attach_target_unknown", Program: a.Program, Name: a.Target, Detail: "no attach target probe"}), nil
	}
	has, err := tc.HasAttachTarget(a.AttachType, a.TargetKind, a.TargetValue)
	switch {
	case errors.Is(err, ErrUnknown):
		out = append(out, Unmet{Kind: "attach_target_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()})
	case err != nil:
		return nil, err
	case !has:
		out = append(out, Unmet{Kind: "attach_target", Program: a.Program, Name: a.Target, Detail: a.AttachType})
	}
	return out, nil
}

// checkCtxAccesses checks attach_type (unless '-') and ctx_access for each row.
func checkCtxAccesses(req *Requirements, caps Capabilities, asked map[string]bool) ([]Unmet, error) {
	var out []Unmet
	cc, ok := capsAs[CtxAccessCaps](caps, QueryCtxAccess)
	for _, c := range req.CtxAccesses {
		u, err := checkAttachType(req, c.Program, c.AttachType, caps, asked)
		if err != nil {
			return nil, err
		}
		out = append(out, u...)
		name := fmt.Sprintf("%s.%s (%s, %d bytes)", c.Struct, c.Field, c.Mode, c.Bytes)
		if !ok {
			out = append(out, Unmet{Kind: "ctx_access_unknown", Program: c.Program, Name: name, Detail: "no ctx access probe"})
			continue
		}
		p, _ := programOf(req, c.Program)
		allowed, err := cc.AllowsCtxAccess(p.ProgType, p.ProgTypeID, c.AttachType, c.Struct, c.Field, c.Mode, c.Bytes)
		switch {
		case errors.Is(err, ErrUnknown):
			out = append(out, Unmet{Kind: "ctx_access_unknown", Program: c.Program, Name: name, Detail: err.Error()})
		case err != nil:
			return nil, err
		case !allowed:
			out = append(out, Unmet{Kind: "ctx_access", Program: c.Program, Name: name, Detail: p.ProgType + " / " + c.AttachType})
		}
	}
	return out, nil
}

// checkFmodRet reports signature mismatches as attach, indeterminate signatures
// as retsig_unknown, and integer argument mismatches as farg/farg_unknown.
// Unknown signatures/arguments block: wrong types can pass the verifier while
// reading incorrect values. Function presence uses attach/attach_func_unknown.
// Keep Unmet Kind literals for source-inspecting spec tests.
func checkFmodRet(a Attach, caps Capabilities) ([]Unmet, error) {
	if a.RetNargs < 0 {
		return nil, fmt.Errorf("program %s: fmod_ret attach row without a retsig row", a.Program)
	}
	var out []Unmet
	if ks, ok := capsAs[KernelFuncSigs](caps, QueryFuncSig); !ok {
		out = append(out, Unmet{Kind: "retsig_unknown", Program: a.Program, Name: a.Target})
	} else {
		diffs, err := ks.CheckFuncSig(a.Target, a.RetNargs, a.RetType)
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.Target, Detail: d})
		}
	}
	for i, t := range a.FArgs {
		if t == "-" {
			continue
		}
		name := fmt.Sprintf("%d of %s (%s)", i+1, a.Target, t)
		fp, ok := capsAs[KernelFuncParams](caps, QueryFuncParam)
		if !ok {
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: name, Detail: "no BTF probe"})
			continue
		}
		diffs, err := fp.CheckFuncParam(a.Target, i+1, t)
		if errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "farg", Program: a.Program, Name: name, Detail: fmt.Sprintf("program %s: %s", a.Program, d)})
		}
	}
	kf, ok := capsAs[KernelFuncs](caps, QueryFunc)
	if !ok {
		return append(out, Unmet{Kind: "attach_func_unknown", Program: a.Program, Name: a.Target}), nil
	}
	diffs, err := kf.CheckFunc(a.Target)
	if err != nil {
		return nil, err
	}
	for _, d := range diffs {
		out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.Target, Detail: d})
	}
	return out, nil
}

// SockmapLinkProgType identifies sk_skb/sk_msg BPF_LINK_CREATE attachments,
// matching LiveCaps sockmapLinkAttach. Their attach_type diagnostics identify
// link creation failures.
func SockmapLinkProgType(progType string) bool { return progType == "sk_skb" || progType == "sk_msg" }

// MultiLinkAttachType identifies trace_kprobe_multi/trace_uprobe_multi.
// LiveCaps multiLinkAttach also probes link creation; attach_type diagnostics
// identify that stage's failures.
func MultiLinkAttachType(attachType string) bool {
	return attachType == "trace_kprobe_multi" || attachType == "trace_uprobe_multi"
}
