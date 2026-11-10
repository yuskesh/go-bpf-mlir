package requirements

import (
	"fmt"
	"strings"
)

// Tables mirror docs/requirements_format.md; spec_test checks document/source
// agreement, so synchronize heading/column changes there.
//
// RowKind describes a section-3 row. Fields counts tab-separated fields,
// including the kind name (map has four in version 1); MinVersion is the
// first format that can contain the row.
type RowKind struct {
	Name       string
	Fields     int
	MinVersion int
}

// RowKinds follows specification section 3 order. Parse uses its field counts
// and minimum versions.
var RowKinds = []RowKind{
	{"schema", 3, 2},
	{"program", 4, 1},
	{"helper", 4, 1},
	{"map", 8, 1},
	{"kfield", 5, 3},
	{"attach", 4, 4},
	{"arg", 4, 4},
	{"retsig", 4, 4},
	{"arch", 3, 4},
	{"ctxfield", 6, 4},
	{"kprobearg", 4, 4},
	{"binary", 4, 4},
	{"uprobearg", 4, 4},
	{"btf", 2, 5},
	{"argtag", 4, 6},
	{"tailslot", 4, 7},
	{"farg", 4, 8},
	{"ctxaccess", 7, 9},      // Context field reads/writes.
	{"tpfield", 6, 11},       // trace_tp event field, checked against tracefs format.
	{"extret", 4, 11},        // freplace replacement argument count and return type.
	{"extarg", 4, 11},        // freplace replacement integer argument type.
	{"structop", 4, 11},      // Struct member implemented by trace_struct_ops.
	{"mtarget", 4, 12},       // Function/symbol i in a multi-probe family.
	{"usdtsem", 3, 12},       // USDT semaphore-presence declaration.
	{"usdtarg", 4, 12},       // USDT argument n width and sign.
	{"innermap", 8, 12},      // Inner template immediately after an array_of_maps/hash_of_maps row.
	{"arena", 2, 29},         // an arena map (after its map row); the loader must keep addr_space_cast and mmap it at map_extra.
	{"kfunc", 4, 13},         // Program-named kfunc signature; 4..9 fields (RowMaxFields).
	{"sysarg", 4, 13},        // ksyscall syscall argument n type.
	{"mtargetarg", 5, 13},    // Multi target i argument n type, after all N mtarget rows.
	{"tpbuf", 3, 14},         // Writable raw tracepoint args[0] must be signed i32*.
	{"enumval", 5, 20},       // Kernel enum constant value of a program.
	{"fibflags", 4, 21},      // bpf_fib_lookup flag name and mask per program.
	{"datakptr", 2, 23},      // a .data.<name> section of hidden kptr globals (loader must not mmap it).
	{"ksymvar", 5, 24},       // a per-CPU typed ksym VAR (slot type, weak / strong); 5 fields, or more with a guarded suffix.
	{"kconfig", 4, 24},       // a CONFIG_* extern (value type, weak / strong); never guarded.
	{"guard", 4, 24},         // an existence guard (ksym / type / field) numbered 0, 1, … in row order.
	{"coreenum", 4, 26},      // a kernel enum constant a program reads through a CO-RE enum value relocation (existence only).
	{"funcret", 3, 27},       // a fexit attach's return type only (ctx.func_ret — no argument count); exclusive with retsig.
	{"kstructsize", 3, 28},   // an embedded kernel struct of N bytes (bpf_cpumask); every row checked against the target size.
	{"helper_target", 8, 31}, // well-typed helper acceptance at the actual target.
	{"sleepable", 2, 32},     // a sleepable trace_fentry attach (directly after its attach row); the program loads with BPF_F_SLEEPABLE.
}

// GuardedRows may carry a trailing "guarded <g> …" suffix after their
// RowKinds field count (format 24): ksymvar and kfield.
var GuardedRows = map[string]bool{"ksymvar": true, "kfield": true}

// RowMaxFields bounds variable-length rows: kfunc has 4..9 fields for 0..5
// arguments. Other rows require exactly RowKinds.Fields (section 3).
var RowMaxFields = map[string]int{"kfunc": 9}

// MaxFormatVersion is the largest header version accepted by Parse; accepted
// formats are 1..MaxFormatVersion. See specification section 2 for row minima
// and section 9 for the separate policy history.
const MaxFormatVersion = 32 // sleepable fentry companion row; older row minima remain unchanged.

// MaxParsedVersion preserves the previous public name for compatibility.
const MaxParsedVersion = MaxFormatVersion

// PolicyVersion versions semantic checking, independently of text format.
// Changes to Unmet kinds, BlocksLoad or Unknown handling require a bump and
// an entry in docs/requirements_format.md section 9. That table records the
// ABI, typed-attach, loader-declaration and query-policy history.
const PolicyVersion = 27 // sleepable_type / sleepable_type_unknown.

// ParseError names the rejected one-based line (header 1; end checks 0), row
// kind (empty for header, unknown kind or document-wide rules) and Rule*.
// Corpus wants compare these stable fields (specification section 10).
type ParseError struct {
	Line int
	Row  string
	Rule string
	msg  string
}

func (e *ParseError) Error() string { return e.msg }

// Parse error rules.
const (
	RuleHeader      = "header"
	RuleFields      = "fields"
	RuleMinVersion  = "min_version"
	RuleOrder       = "order"
	RuleValue       = "value"
	RuleUnknownKind = "unknown_kind"
	RuleDocument    = "document"
	// the binding of guarded suffixes to guard rows.
	RuleGuardOrphan  = "guard_orphan"  // A guarded number has no guard row.
	RuleGuardUnused  = "guard_unused"  // A guard row no guarded suffix lists.
	RuleGuardTarget  = "guard_target"  // A guard whose target is not the marked row's target.
	RuleGuardStrong  = "guard_strong"  // A guarded suffix on a strong ksymvar.
	RuleGuardKind    = "guard_kind"    // A guarded suffix on a row kind other than ksymvar / kfield.
	RuleGuardOrder   = "guard_order"   // Guard numbering, guard row order or guarded list order.
	RuleGuardMissing = "guard_missing" // A weak ksymvar without a guarded suffix.
)

// GuardRules lists the binding rules (specification section 3).
var GuardRules = []string{RuleGuardOrphan, RuleGuardUnused, RuleGuardTarget, RuleGuardStrong, RuleGuardKind, RuleGuardOrder, RuleGuardMissing}

func perr(line int, row, rule, format string, args ...any) error {
	return &ParseError{Line: line, Row: row, Rule: rule, msg: fmt.Sprintf(format, args...)}
}

// AttachTypes lists families with companion rows (specification section 4),
// including return probes, typed tracing/ext/struct_ops, multi probes and USDT.
// Multi targets are counts followed by mtarget; USDT uses <provider>:<name>.
var AttachTypes = []string{"trace_raw_tp", "trace_fentry", "trace_fexit", "kprobe", "uprobe", "tcx", "netkit", "kretprobe", "uretprobe", "trace_fmod_ret",
	"trace_lsm", "trace_tp", "trace_perf", "freplace", "trace_struct_ops",
	"kprobe_multi", "kretprobe_multi", "uprobe_multi", "uretprobe_multi", "usdt",
	"trace_lsm_cgroup", "ksyscall"} // legacyAttachTypes are accepted only in formats 4..8.
var legacyAttachTypes = []string{"trace_raw_tp", "trace_fentry", "trace_fexit", "kprobe", "uprobe", "tcx"}

// GenericAttachMinVersion is the minimum for companion-free generic attach
// rows and return-probe families.
const GenericAttachMinVersion = 9

// FmodRetMinVersion introduces trace_fmod_ret with retsig and integer farg.
const FmodRetMinVersion = 10

// TypedAttachMinVersion introduces typed trace_lsm/trace_tp/trace_perf/
// freplace/trace_struct_ops and tpfield/extret/extarg/structop rows.
const TypedAttachMinVersion = 11

// CompanionV11MinVersion is a format version, not a release version.
// Deprecated: use TypedAttachMinVersion.
const CompanionV11MinVersion = TypedAttachMinVersion

// isTypedAttachType identifies the format-11 typed attach families.
func isTypedAttachType(t string) bool {
	switch t {
	case "trace_lsm", "trace_tp", "trace_perf", "freplace", "trace_struct_ops":
		return true
	}
	return false
}

// MultiAndInnerMapMinVersion introduces multi/USDT families and their companions plus innermap.
const MultiAndInnerMapMinVersion = 12

// V12MinVersion is a format version, not a release version.
// Deprecated: use MultiAndInnerMapMinVersion.
const V12MinVersion = MultiAndInnerMapMinVersion

// isMultiAttachType identifies families whose positive target count requires
// exactly N subsequent mtarget rows.
func isMultiAttachType(t string) bool {
	switch t {
	case "kprobe_multi", "kretprobe_multi", "uprobe_multi", "uretprobe_multi":
		return true
	}
	return false
}

// isMultiOrUSDTAttachType identifies multi-probe and USDT families.
func isMultiOrUSDTAttachType(t string) bool { return isMultiAttachType(t) || t == "usdt" }

// isUprobeFamily identifies single/multi user probes and USDT with binary rows.
func isUprobeFamily(t string) bool {
	switch t {
	case "uprobe", "uretprobe", "uprobe_multi", "uretprobe_multi", "usdt":
		return true
	}
	return false
}

// attachTypeMinVersion returns the specification section 2 minimum for the
// attach family; legacy forms start at 4, generic/return forms at 9,
// trace_fmod_ret at 10, typed companions at 11 and multi/USDT at 12.
func attachTypeMinVersion(t string) int {
	switch {
	case t == "netkit":
		return NetkitMinVersion
	case isLegacyAttachType(t):
		return 4
	case t == "trace_fmod_ret":
		return FmodRetMinVersion
	case isTypedAttachType(t):
		return TypedAttachMinVersion
	case isMultiOrUSDTAttachType(t):
		return MultiAndInnerMapMinVersion
	case isSyscallOrLSMCgroupAttachType(t):
		return KfuncAndSyscallMinVersion
	}
	return GenericAttachMinVersion
}

// AttachMechanisms names mechanisms without expected_attach_type; their generic
// rows do not query attach_type and load with expected_attach_type zero. Other
// generic types use lowercase bpf_attach_type names without BPF_. Adding a
// mechanism requires a format bump (specification section 4).
var AttachMechanisms = []string{"raw_tp", "raw_tp_writable", "tracepoint", "socket_filter", "sched_act", "lwt_in", "lwt_out", "lwt_xmit", "lwt_seg6local", "syscall"}

// AttachTargetKind describes a generic attach target. Value selects whether
// <kind>:<value> is required (specification section 4).
type AttachTargetKind struct {
	Name  string
	Value bool
}

// AttachTargetKinds lists target kinds. Value-bearing targets query
// attach_target; map references must also name a map row in the same ELF.
var AttachTargetKinds = []AttachTargetKind{
	{"func", true}, {"tp", true}, {"rawtp", true}, {"iter", true}, {"lsm", true}, {"sym", true}, {"map", true}, {"prog", true},
	{"cgroup", false}, {"netns", false}, {"socket", false}, {"netlink", false}, {"perf", false}, {"device", false}, {"none", false},
}

func rowKind(name string) (RowKind, bool) {
	for _, k := range RowKinds {
		if k.Name == name {
			return k, true
		}
	}
	return RowKind{}, false
}

func minVersion(name string) int {
	k, _ := rowKind(name)
	return k.MinVersion
}

// UnmetKind mirrors the section 6 table. spec_test verifies Unknown and
// BlocksLoad against Unmet.Unknown and Unmet.BlocksLoad.
type UnmetKind struct {
	Kind       string
	Unknown    bool
	BlocksLoad bool
}

// UnmetKinds lists all Check outcomes in specification section 6 order.
var UnmetKinds = []UnmetKind{
	{"program_type", false, true},
	{"helper", false, true},
	{"helper_unknown", true, false},
	{"helper_target", false, true},
	{"helper_target_unknown", true, true},
	{"attach", false, true},
	{"attach_tcx_unknown", true, false},
	{"attach_netkit_unknown", true, false},
	{"retsig_unknown", true, true},
	{"farg", false, true},
	{"farg_unknown", true, true},
	{"attach_func_unknown", true, false},
	{"arg_nullable_unknown", true, false},
	{"arg_nullable", false, true},
	{"arg_nullable_mark_unknown", true, true},
	{"kfield", false, true},
	{"attach_unknown", true, true},
	{"kfield_unknown", true, true},
	{"btf_feature", false, true},
	{"btf_feature_unknown", true, true},
	{"btf_rewrite", false, true},
	{"arg_tag", false, true},
	{"arg_tag_unknown", true, true},
	{"map_type", false, true},
	{"arch", false, true},
	{"arch_unknown", true, true},
	{"ctxfield", false, true},
	{"ctxfield_unknown", true, true},
	{"attach_symbol_unknown", true, true},
	{"attach_alias", false, true},
	{"attach_alias_unknown", true, true},
	{"kprobearg", false, true},
	{"kprobearg_unknown", true, true},
	{"binary", false, true},
	{"binary_unknown", true, true},
	{"uprobe_symbol", false, true},
	{"uprobe_debug_build_id", false, true},
	{"uprobe_debug_crc", false, true},
	{"uprobearg", false, true},
	{"uprobearg_unknown", true, true},
	{"uprobearg_abi", false, true},        // Known non-SysV target: Go ABIInternal or nonnormal calling convention.
	{"uprobearg_abi_unknown", true, true}, // Target CU language absent or not C-family.
	{"map_field", false, true},
	{"map_field_unknown", true, false},
	{"attach_type", false, true},              // Kernel rejects expected_attach_type for this program type.
	{"attach_type_unknown", true, false},      // Indeterminate; kernel load rejects loudly.
	{"attach_target", false, true},            // Named function/tracepoint/iterator/LSM hook absent from target kernel.
	{"attach_target_unknown", true, false},    // Indeterminate; attachment fails loudly.
	{"ctx_access", false, true},               // Verifier rejects this context field access.
	{"ctx_access_unknown", true, false},       // Indeterminate; verifier rejects loudly.
	{"fibflags", false, true},                 // target bpf_fib_lookup rejects the flag mask for the program type.
	{"fibflags_unknown", true, true},          // indeterminate; a rejected mask is only seen at run time.
	{"uretprobe_abi", false, true},            // Return-probe target known non-SysV.
	{"uretprobe_abi_unknown", true, true},     // Return-probe CU language/subprogram evidence missing or not C-family.
	{"tpfield", false, true},                  // Tracepoint field absent or offset/size/sign differs from tracefs.
	{"tpfield_unknown", true, true},           // Format unreadable or tracepoint_fields unrecorded; use recorded root caps.
	{"ext_target", false, true},               // Replacement function linkage, argument count/types or return differs.
	{"ext_target_unknown", true, true},        // No replacement, BTF or function evidence supplied.
	{"structop", false, true},                 // struct_ops member absent, not a function pointer or signature differs.
	{"structop_unknown", true, true},          // BTF absent or struct exists only in an unavailable module.
	{"usdt_probe", false, true},               // Missing USDT point or semaphore presence differs.
	{"usdtarg", false, true},                  // USDT argument count/width/sign differs, identifying the point PC.
	{"usdtarg_unknown", true, true},           // USDT location unreadable: SIB, unknown register/spelling or malformed note.
	{"usdt_loader", false, true},              // Loader cannot attach USDT or cannot supply a required semaphore ref_ctr_offset.
	{"usdt_loader_unknown", true, true},       // USDT attach declaration absent.
	{"kfunc_sig", false, true},                // Target kfunc absent or FUNC_PROTO count/types/return differs.
	{"kfunc_sig_unknown", true, true},         // BTF unreadable or kfunc_protos unrecorded.
	{"kfunc_allowed", false, true},            // Named rejection of kfunc use under the exact program profile.
	{"kfunc_allowed_unknown", true, false},    // Recipe/profile/permission indeterminate; kernel load rejects loudly.
	{"sysarg", false, true},                   // Syscall argument absent or width/sign/pointer differs.
	{"sysarg_unknown", true, true},            // Tracefs unreadable or both syscall event and __do_sys_ evidence absent.
	{"lsm_cgroup_loader", false, true},        // Loader cannot load lsm_cgroup (none).
	{"lsm_cgroup_loader_unknown", true, true}, // lsm_cgroup load declaration absent.
	{"fsession_loader", false, true},          // Loader cannot load fsession (none).
	{"fsession_loader_unknown", true, true},   // fsession load declaration absent.
	{"ksyscall_loader", false, true},          // Loader does not attach ksyscall to the architecture-prefixed wrapper.
	{"ksyscall_loader_unknown", true, true},   // ksyscall attach declaration absent.
	{"enumval", false, true},                  // Target enum constant absent or its value differs.
	{"enumval_unknown", true, true},           // Enum values unreadable or enum_values unrecorded.
	{"coreenum", false, true},                 // target enum constant of a CO-RE enum value relocation absent (the loader poisons the instruction).
	{"coreenum_unknown", true, true},          // enum values unreadable or enum_values unrecorded.
	{"funcret", false, true},                  // fexit target absent, or its return is not an integer of the funcret width / sign (void included).
	{"funcret_unknown", true, true},           // func_ret unrecorded / Unknown — the return type is unconfirmed.
	{"kstructsize", false, true},              // the target struct is larger than an embedded N, or absent.
	{"kstructsize_unknown", true, true},       // kstruct_size unrecorded / Unknown — the struct size is unconfirmed.
	{"datakptr_loader", false, true},          // loader mmaps hidden data variables; the kernel refuses mmap of a kptr map (-ENOTSUPP).
	{"datakptr_loader_unknown", true, true},   // hidden_data_vars declaration absent.
	{"arena_loader", false, true},             // the loader rewrites addr_space_cast (corrupt) or does not mmap the arena at map_extra (none).
	{"arena_loader_unknown", true, true},      // arena_cast / arena_premmap declaration absent.
	{"typed_ksym_loader", false, true},        // the loader writes a kallsyms address, not BPF_PSEUDO_BTF_ID (per_cpu_ptr rejects it).
	{"typed_ksym_loader_unknown", true, true}, // typed_ksym declaration absent.
	{"ksymvar", false, true},                  // VAR absent (strong or unexcused weak), not per-CPU, or another slot type.
	{"ksymvar_unknown", true, true},           // ksym_vars absent / Unknown, or a guard not confirmed.
	{"kconfig_loader", false, true},           // weak CONFIG_* under a strong_only loader.
	{"kconfig_loader_unknown", true, true},    // kconfig declaration absent.
	{"kconfig", false, true},                  // a strong CONFIG_* not set in the kconfig file.
	{"kconfig_type", false, true},             // the value does not fit the extern's type (libbpf rejects it).
	{"kconfig_unknown", true, true},           // kconfig file missing / unreadable / malformed, or no query.
	{"sleepable_type", false, true},           // the target kernel cannot load this program type / attach type pair sleepable.
	{"sleepable_type_unknown", true, false},   // no sleepable_types query, or the probe could not separate a type refusal; the kernel refuses loudly.
}

func knownAttachType(t string) bool {
	for _, a := range AttachTypes {
		if a == t {
			return true
		}
	}
	return false
}

// isLegacyAttachType identifies formats 4..8 attach types.
func isLegacyAttachType(t string) bool {
	for _, a := range legacyAttachTypes {
		if a == t {
			return true
		}
	}
	return false
}

// isProbeAttach identifies families with arch/ctxfield companions: single and
// multi kernel/user probes and USDT.
func isProbeAttach(t string) bool {
	return t == "kprobe" || t == "uprobe" || t == "kretprobe" || t == "uretprobe" || isMultiOrUSDTAttachType(t) || t == "ksyscall" // ksyscall uses arch -> ctxfield -> sysarg.
}

// isAttachMechanism identifies a mechanism without expected_attach_type.
func isAttachMechanism(t string) bool {
	for _, m := range AttachMechanisms {
		if m == t {
			return true
		}
	}
	return false
}

// validAttachTypeName accepts lowercase-leading [a-z0-9_]+ names. Actual UAPI
// or mechanism availability is checked by attach_type.
func validAttachTypeName(s string) bool {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// validCName accepts C identifiers, including __sk_buff.
func validCName(s string) bool {
	if s == "" || s[0] >= '0' && s[0] <= '9' {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// parseAttachTarget requires a nonempty value exactly when the kind has Value,
// otherwise refuses a value. No spaces/tabs are allowed; tracepoints use
// <category>/<name>.
func parseAttachTarget(s string) (kind, value string, err error) {
	kind, value, hasValue := strings.Cut(s, ":")
	for _, k := range AttachTargetKinds {
		if k.Name != kind {
			continue
		}
		switch {
		case k.Value && (!hasValue || value == "" || strings.ContainsAny(value, " \t")):
			return "", "", fmt.Errorf("target kind %q needs a value (%s:<value>)", kind, kind)
		case !k.Value && hasValue:
			return "", "", fmt.Errorf("target kind %q takes no value (the loader supplies it)", kind)
		}
		return kind, value, nil
	}
	return "", "", fmt.Errorf("unknown target kind %q", kind)
}

// hasMap checks whether a map row declares the symbol.
func (r *Requirements) hasMap(sym string) bool {
	for _, m := range r.Maps {
		if m.Symbol == sym {
			return true
		}
	}
	return false
}
