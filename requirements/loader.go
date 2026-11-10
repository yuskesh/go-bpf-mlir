package requirements

// LoaderDecl separates loader behavior from kernel capability facts. The same
// kernel can behave differently under different loaders. Check combines
// KprobeAliasPrefix (L2) and BTFRewrite (L1) with kernel queries; L3/L4 document
// caller obligations and why prechecking is required. BTF rewrite decisions
// combine feature acceptance with the loader's declared handling. See
// docs/requirements_format.md section 8 for rules and preset evidence.
type LoaderDecl struct {
	// Name identifies the declaration, e.g. cilium-v0.22.
	Name string
	// KprobeAliasPrefix maps target architecture to the retry prefix (L2).
	// Empty means no retry; an absent architecture is blocking attach_alias_unknown.
	KprobeAliasPrefix map[string]string
	// UprobeReopensPath says whether symbol resolution can reopen a different
	// file than the checked descriptor (L3).
	UprobeReopensPath bool
	// COREPoisonsMissingField says whether missing fields become invalid
	// runtime instructions instead of relocation errors (L4).
	COREPoisonsMissingField bool
	// BTFRewrite maps each rewritable feature to rewrite or keep (L1). Silent
	// rewriting blocks with btf_rewrite; keep lets the kernel reject loudly.
	// Undeclared features are blocking btf_feature_unknown.
	BTFRewrite map[string]string
	// USDTAttach is none, plain uprobes without ref_ctr_offset, or ref_ctr
	// for semaphore support. Empty is blocking usdt_loader_unknown.
	USDTAttach string
	// SockmapAttach selects link/BPF_LINK_CREATE or prog_attach/BPF_PROG_ATTACH
	// (available since 4.17) for sk_skb/sk_msg. Link attachment fails on kernels
	// lacking sockmap links. Empty uses the stricter link decision.
	SockmapAttach string
	// LSMCgroupLoad/FsessionLoad select BTF-ID-aware loading or none. Empty
	// produces blocking lsm_cgroup_loader_unknown/fsession_loader_unknown.
	LSMCgroupLoad string
	FsessionLoad  string
	// KsyscallAttach selects an architecture-prefixed wrapper (__x64_sys_<name>)
	// or none. cilium v0.22's bare section-suffix name fails loudly. Empty
	// produces blocking ksyscall_loader_unknown.
	KsyscallAttach string
	// HiddenDataVars says whether the loader mmaps hidden (STV_HIDDEN) global
	// variables of a data section: no_mmap or mmap. The kernel refuses
	// mmap of a map whose record has a kptr (-ENOTSUPP), so a datakptr row needs
	// no_mmap; mmap blocks with datakptr_loader and empty with
	// datakptr_loader_unknown. cilium v0.22 creates the .data.<name> map
	// MMAPABLE but makes no Variable for a hidden symbol, so never mmaps it.
	HiddenDataVars string
	// TypedKsym says how the loader resolves a typed ksym VAR: btf_id
	// (ld_imm64 BPF_PSEUDO_BTF_ID — the verifier types the register from the
	// VAR's BTF) or kallsyms_addr (the kallsyms address as a plain immediate,
	// a scalar that bpf_per_cpu_ptr's ARG_PTR_TO_PERCPU_BTF_ID rejects).
	// kallsyms_addr blocks a ksymvar row with typed_ksym_loader, empty with
	// typed_ksym_loader_unknown.
	TypedKsym string
	// Kconfig says how the loader resolves CONFIG_* externs: weak_zero
	// (an unset weak extern reads 0, as raw libbpf does) or strong_only (weak
	// .kconfig externs are refused). strong_only blocks a weak kconfig row with
	// kconfig_loader, empty with kconfig_loader_unknown.
	Kconfig string
	// ArenaCast says whether the loader passes the program's instructions to
	// the kernel byte for byte (preserve) or rewrites an addr_space_cast
	// (corrupt). corrupt blocks an arena row with arena_loader, empty with
	// arena_loader_unknown.
	ArenaCast string
	// ArenaPremmap says whether the loader mmaps an arena map at its map_extra
	// address right after creating it, sharing it with userspace
	// (create_then_mmap), or does not (none). none blocks an arena row
	// with arena_loader, empty with arena_loader_unknown.
	ArenaPremmap string
}

// Loader declaration values.
const (
	SockmapAttachLink       = "link"
	SockmapAttachProgAttach = "prog_attach"
	ProgLoadNone            = "none"
	ProgLoadBTFID           = "btf_id"
	KsyscallAttachNone      = "none"
	KsyscallAttachPrefix    = "prefix"
	HiddenDataVarsNoMmap    = "no_mmap" // hidden data variables are never mmapped.
	HiddenDataVarsMmap      = "mmap"
	TypedKsymBTFID          = "btf_id"        // ld_imm64 BPF_PSEUDO_BTF_ID (raw libbpf).
	TypedKsymKallsymsAddr   = "kallsyms_addr" // a kallsyms address immediate (cilium v0.22).
	KconfigWeakZero         = "weak_zero"     // unset weak CONFIG_* reads 0 (raw libbpf).
	KconfigStrongOnly       = "strong_only"   // weak .kconfig externs are refused (cilium v0.22).
)

// Arena loader declaration values.
const (
	ArenaCastPreserve          = "preserve"         // Instructions reach the kernel byte for byte (libbpf v1.7.0).
	ArenaCastCorrupt           = "corrupt"          // addr_space_cast is rewritten (cilium v0.22 — U3).
	ArenaPremmapCreateThenMmap = "create_then_mmap" // mmap(map_extra, MAP_SHARED|MAP_FIXED) right after create (libbpf v1.7.0).
	ArenaPremmapNone           = "none"             // No mmap at map_extra (cilium v0.22).
)

// validDeclValues validates loader fields; empty means undeclared.
func validDeclValue(key, v string) bool {
	if v == "" {
		return true
	}
	switch key {
	case "sockmap_attach":
		return v == SockmapAttachLink || v == SockmapAttachProgAttach
	case "lsm_cgroup_load", "fsession_load":
		return v == ProgLoadNone || v == ProgLoadBTFID
	case "ksyscall_attach":
		return v == KsyscallAttachNone || v == KsyscallAttachPrefix
	case "hidden_data_vars":
		return v == HiddenDataVarsNoMmap || v == HiddenDataVarsMmap
	case "typed_ksym":
		return v == TypedKsymBTFID || v == TypedKsymKallsymsAddr
	case "kconfig":
		return v == KconfigWeakZero || v == KconfigStrongOnly
	case "arena_cast":
		return v == ArenaCastPreserve || v == ArenaCastCorrupt
	case "arena_premmap":
		return v == ArenaPremmapCreateThenMmap || v == ArenaPremmapNone
	}
	return false
}

// USDTAttach values.
const (
	USDTAttachNone   = "none"
	USDTAttachPlain  = "plain"
	USDTAttachRefCtr = "ref_ctr"
)

// ValidUSDTAttach validates usdt_attach; empty means undeclared/unknown.
func ValidUSDTAttach(s string) bool {
	switch s {
	case "", USDTAttachNone, USDTAttachPlain, USDTAttachRefCtr:
		return true
	}
	return false
}

// BTFRewrite values.
const (
	BTFRewriteRewrite = "rewrite"
	BTFRewriteKeep    = "keep"
)

// BTFRewritable matches the four cilium btf.KernelMarshalOptions rewrite flags.
var BTFRewritable = []string{"func_global", "decl_tag", "type_tag", "enum64"}

// btfRewriteNames maps features to rewrite names used in Unmet diagnostics.
var btfRewriteNames = map[string]string{
	"func_global": "StripFuncLinkage (global FUNC → static)",
	"decl_tag":    "ReplaceDeclTags",
	"type_tag":    "ReplaceTypeTags",
	"enum64":      "ReplaceEnum64",
}

// LoaderCaps supplies the loader declaration. Without it, Check uses Cilium022.
type LoaderCaps interface {
	Loader() LoaderDecl
}

// Cilium022 declares cilium/ebpf v0.22 behavior documented in section 8.
var Cilium022 = LoaderDecl{
	Name:                    "cilium-v0.22",
	KprobeAliasPrefix:       map[string]string{"x86_64": "__x64_"},
	UprobeReopensPath:       true,
	COREPoisonsMissingField: true,
	// KernelMarshalOptions silently rewrites features whose kernel probes fail.
	BTFRewrite: map[string]string{"func_global": BTFRewriteRewrite, "decl_tag": BTFRewriteRewrite, "type_tag": BTFRewriteRewrite, "enum64": BTFRewriteRewrite},
	// cilium v0.22 recognizes usdt+ as kprobe type but does not implement
	// USDT note reading or the argument-spec map.
	USDTAttach: USDTAttachNone,
	// Default sockmap attach uses BPF_LINK_CREATE. Explicit PROG_ATTACH glue
	// has a separate preset. cilium cannot load lsm_cgroup/fsession because
	// findProgramTargetInKernel leaves attach_btf_id zero; its ksyscall
	// attachment uses the bare section-suffix name and fails.
	SockmapAttach:  SockmapAttachLink,
	LSMCgroupLoad:  ProgLoadNone,
	FsessionLoad:   ProgLoadNone,
	KsyscallAttach: KsyscallAttachNone,
	// collection.go:415-417 sets BPF_F_MMAPABLE on every data section by
	// name, but elf_reader.go:1359-1363 makes no VariableSpec for a hidden symbol
	// and NewCollection mmaps only Variables (collection.go:285-306).
	HiddenDataVars: HiddenDataVarsNoMmap,
	// linker.go:455-519 (resolveKsymReferences) writes the kallsyms
	// address of a typed ksym into the ld_imm64 immediate without
	// BPF_PSEUDO_BTF_ID, so the verifier sees a scalar and bpf_per_cpu_ptr's
	// ARG_PTR_TO_PERCPU_BTF_ID rejects it (verifier.c:8880-8887 in 7.3.1).
	TypedKsym: TypedKsymKallsymsAddr,
	// elf_reader.go:779-782 rejects a .kconfig relocation whose symbol is
	// not STB_GLOBAL, so only strong CONFIG_* externs load.
	Kconfig: KconfigStrongOnly,
	// the asm Marshal writes addr_space_cast with its offset 1 as 0,
	// and 7.1.8 rejects the program with "BPF_MOV uses reserved fields" (seen in
	// an earlier probe). Map.Memory() mmaps at address 0, while the kernel requires the
	// exact map_extra address of such an arena (7.1.8 arena.c:454-461), so the
	// arena is never shared with userspace.
	ArenaCast:    ArenaCastCorrupt,
	ArenaPremmap: ArenaPremmapNone,
}

// LoaderDependentKinds lists outcomes that depend on declarations, covered by
// corpus cases for each preset: aliases use KprobeAliasPrefix, BTF rewrites use
// BTFRewrite, USDT uses USDTAttach, sockmap attach_type uses SockmapAttach, and
// lsm_cgroup/fsession/ksyscall loader outcomes use their corresponding fields.
// datakptr_loader / _unknown are not here — cilium declares no_mmap (no
// cilium case yields them); each preset has its own case in bindrt
// conformance_e615_datakptr_test.go.
// typed_ksym_loader / kconfig_loader and their _unknown are here — cilium
// declares kallsyms_addr / strong_only, so a cilium case yields the definite
// kinds and its bml twin the _unknown ones (bml declares neither).
// arena_loader / _unknown are here — cilium declares corrupt / none (a
// cilium case yields arena_loader); bml declares preserve / create_then_mmap,
// and partial declarations yield arena_loader_unknown (conformance_e640_arena_test.go).
var LoaderDependentKinds = []string{"attach_alias", "attach_alias_unknown", "btf_rewrite", "usdt_loader", "usdt_loader_unknown",
	"attach_type", "lsm_cgroup_loader", "lsm_cgroup_loader_unknown", "fsession_loader", "fsession_loader_unknown", "ksyscall_loader", "ksyscall_loader_unknown",
	"typed_ksym_loader", "typed_ksym_loader_unknown", "kconfig_loader", "kconfig_loader_unknown", "arena_loader", "arena_loader_unknown"}

// BmlLibbpf17 declares the guarded bpf-mlir-loader with pinned libbpf v1.7.0,
// not raw libbpf, which does not satisfy the section 8 contract. Guards refuse
// predicted BTF rewrites, so all four features are keep; there is no kprobe
// alias retry on x86_64. Uprobe paths reopen and missing CO-RE fields poison.
// USDT remains undeclared and blocks with usdt_loader_unknown until the loader
// explicitly establishes its behavior. hidden_data_vars is undeclared too
// (libbpf v1.7.0 rewrites hidden VARs static and does not make such a map
// MMAPABLE — libbpf.c:3438-3440, :1930-1954, :1992 — but bml has no load record
// of a hidden data kptr yet), so datakptr rows block with datakptr_loader_unknown.
// typed_ksym and kconfig are undeclared: bpf-mlir-loader
// src/load/pre.c:281 rejects any UND symbol ("symbol %s is undefined (extern —
// libbpf would resolve it)"), so neither btf_id nor weak_zero is inferred from
// libbpf; ksymvar / kconfig rows block with typed_ksym_loader_unknown /
// kconfig_loader_unknown.
// arena_cast / arena_premmap are preserve / create_then_mmap: libbpf
// v1.7.0 mmaps an arena map at map_extra with MAP_SHARED|MAP_FIXED right after
// creating it and fails the load otherwise (libbpf.c:5617-5623), and the
// instructions reach the kernel byte for byte.
var BmlLibbpf17 = LoaderDecl{
	Name:                    "bml-libbpf-v1.7",
	KprobeAliasPrefix:       map[string]string{"x86_64": ""},
	UprobeReopensPath:       true,
	COREPoisonsMissingField: true,
	BTFRewrite: map[string]string{
		"func_global": BTFRewriteKeep, "decl_tag": BTFRewriteKeep, "type_tag": BTFRewriteKeep, "enum64": BTFRewriteKeep,
	},
	ArenaCast:    ArenaCastPreserve,
	ArenaPremmap: ArenaPremmapCreateThenMmap,
}

// Cilium022USDT adds AttachUSDT glue: read notes, populate argument specs and
// attach uprobes with Address/Cookie/RefCtrOffset. Only usdt_attach changes to
// ref_ctr; all other behavior remains cilium v0.22.
var Cilium022USDT = func() LoaderDecl {
	d := Cilium022
	d.Name = "cilium-v0.22-usdt"
	d.USDTAttach = USDTAttachRefCtr
	return d
}()

// Cilium022ProgAttach adds explicit AttachSockmapProgAttach (RawAttachProgram).
// Only sockmap_attach changes to prog_attach. Callers must select this preset
// and use that attachment path; it is never an automatic fallback.
var Cilium022ProgAttach = func() LoaderDecl {
	d := Cilium022
	d.Name = "cilium-v0.22-progattach"
	d.SockmapAttach = SockmapAttachProgAttach
	return d
}()

// Cilium022Ksyscall adds AttachKsyscall: build the wrapper using KsyscallWrapper,
// attach with Kprobe and check the actual link target. Only ksyscall_attach
// changes to prefix; cilium's section-based bare-name attachment is unchanged.
var Cilium022Ksyscall = func() LoaderDecl {
	d := Cilium022
	d.Name = "cilium-v0.22-ksyscall"
	d.KsyscallAttach = KsyscallAttachPrefix
	return d
}()

// Cilium022USDTKsyscall composes ref_ctr and prefix, changing only those two
// Cilium022 fields. Callers must fulfill both AttachUSDT and AttachKsyscall
// contracts; this adds neither new glue nor automatic fallback.
var Cilium022USDTKsyscall = func() LoaderDecl {
	d := Cilium022USDT
	d.Name = "cilium-v0.22-usdt-ksyscall"
	d.KsyscallAttach = KsyscallAttachPrefix
	return d
}()

// LoaderPresets lists declarations selectable by ebpf-precheck --loader.
var LoaderPresets = map[string]LoaderDecl{Cilium022.Name: Cilium022, BmlLibbpf17.Name: BmlLibbpf17, Cilium022USDT.Name: Cilium022USDT,
	Cilium022ProgAttach.Name: Cilium022ProgAttach, Cilium022Ksyscall.Name: Cilium022Ksyscall, Cilium022USDTKsyscall.Name: Cilium022USDTKsyscall}

func loaderOf(caps Capabilities) LoaderDecl {
	if lc, ok := caps.(LoaderCaps); ok {
		return lc.Loader()
	}
	return Cilium022
}

// kprobeAlias returns the retry prefix for target arch; known false means unknown.
func kprobeAlias(caps Capabilities, arch string) (prefix string, known bool) {
	p, ok := loaderOf(caps).KprobeAliasPrefix[arch]
	return p, ok
}

// Query names used in caps.json; see specification sections 5 and 10.
const (
	QueryProgType      = "prog_type"
	QueryHelper        = "helper"
	QueryMapType       = "map_type"
	QueryTCX           = "tcx"
	QueryNetkit        = "netkit"
	QuerySleepable     = "sleepable_types" // <program type>/<attach type> pair loadable with BPF_F_SLEEPABLE.
	QueryFuncSig       = "func_sig"
	QueryFuncRet       = "func_ret"     // fexit integer return type without nargs.
	QueryKStructSize   = "kstruct_size" // byte size of an embedded kernel struct (bpf_cpumask).
	QueryFunc          = "func"
	QueryTracepoint    = "tracepoint"
	QueryKFields       = "kfields"
	QueryBTFFeature    = "btf_feature"
	QueryArgTag        = "arg_tag"
	QueryArch          = "arch"
	QueryStructField   = "struct_field"
	QueryKernelSym     = "kernel_symbol"
	QueryFuncParam     = "func_param"
	QueryUprobeBin     = "uprobe_binary"
	QueryUprobeDebug   = "uprobe_debug"
	QueryMapField      = "map_field"
	QueryNullableArgs  = "nullable_args"
	QueryTracingHelper = "tracing_helpers"
	QueryFuncArgs      = "func_args" // fentry argument types.
	QueryAttachType    = "attach_types"
	QueryAttachTarget  = "attach_targets"
	QueryCtxAccess     = "ctx_access" // Tracefs event fields, struct_ops members and live replacement targets;
	// replacement programs are loader inputs and are not recorded.
	QueryTracepointFields = "tracepoint_fields"
	QueryStructOpsMembers = "struct_ops_members"
	QueryExtTargets       = "ext_targets"
	// Kernel kfunc FUNC_PROTO and syscall argument types from tracefs or
	// __do_sys_ BTF are privilege-independent queries.
	QueryKfuncProtos = "kfunc_protos"
	QuerySyscallArgs = "syscall_args"
	// kernel enum constant values (BTF ENUM / ENUM64), privilege-independent.
	QueryEnumValues = "enum_values"
	// typed ksym VARs, CONFIG_* values and BTF type / field existence
	// (vmlinux and module BTF, the kconfig file), privilege-independent.
	QueryKsymVars    = "ksym_vars"
	QueryKconfig     = "kconfig"
	QueryBTFPresence = "btf_presence"
)

// QuerySet declares optional queries by name. Recorded caps implement all
// interfaces but lack queries absent from the recording. Without QuerySet,
// availability follows the Go interface set alone.
type QuerySet interface {
	HasQuery(name string) bool
}

// capsAs returns an interface only when caps supplies query q.
func capsAs[T any](caps Capabilities, q string) (T, bool) {
	t, ok := caps.(T)
	if !ok {
		return t, false
	}
	if qs, ok := caps.(QuerySet); ok && !qs.HasQuery(q) {
		var zero T
		return zero, false
	}
	return t, true
}

// loaderLabel supplies the loader name for diagnostics.
func loaderLabel(caps Capabilities) string {
	if n := loaderOf(caps).Name; n != Cilium022.Name {
		return n
	}
	return "cilium/ebpf link.Kprobe"
}
