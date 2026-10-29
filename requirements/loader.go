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
}

// Loader declaration values.
const (
	SockmapAttachLink       = "link"
	SockmapAttachProgAttach = "prog_attach"
	ProgLoadNone            = "none"
	ProgLoadBTFID           = "btf_id"
	KsyscallAttachNone      = "none"
	KsyscallAttachPrefix    = "prefix"
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
}

// LoaderDependentKinds lists outcomes that depend on declarations, covered by
// corpus cases for each preset: aliases use KprobeAliasPrefix, BTF rewrites use
// BTFRewrite, USDT uses USDTAttach, sockmap attach_type uses SockmapAttach, and
// lsm_cgroup/fsession/ksyscall loader outcomes use their corresponding fields.
var LoaderDependentKinds = []string{"attach_alias", "attach_alias_unknown", "btf_rewrite", "usdt_loader", "usdt_loader_unknown",
	"attach_type", "lsm_cgroup_loader", "lsm_cgroup_loader_unknown", "fsession_loader", "fsession_loader_unknown", "ksyscall_loader", "ksyscall_loader_unknown"}

// BmlLibbpf17 declares the guarded bpf-mlir-loader with pinned libbpf v1.7.0,
// not raw libbpf, which does not satisfy the section 8 contract. Guards refuse
// predicted BTF rewrites, so all four features are keep; there is no kprobe
// alias retry on x86_64. Uprobe paths reopen and missing CO-RE fields poison.
// USDT remains undeclared and blocks with usdt_loader_unknown until the loader
// explicitly establishes its behavior.
var BmlLibbpf17 = LoaderDecl{
	Name:                    "bml-libbpf-v1.7",
	KprobeAliasPrefix:       map[string]string{"x86_64": ""},
	UprobeReopensPath:       true,
	COREPoisonsMissingField: true,
	BTFRewrite: map[string]string{
		"func_global": BTFRewriteKeep, "decl_tag": BTFRewriteKeep, "type_tag": BTFRewriteKeep, "enum64": BTFRewriteKeep,
	},
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
	QueryFuncSig       = "func_sig"
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
	QueryFuncArgs      = "func_args"       // fentry argument types.
	QueryAttachType    = "attach_types"
	QueryAttachTarget  = "attach_targets"
	QueryCtxAccess     = "ctx_access"      // Tracefs event fields, struct_ops members and live replacement targets;
	// replacement programs are loader inputs and are not recorded.
	QueryTracepointFields = "tracepoint_fields"
	QueryStructOpsMembers = "struct_ops_members"
	QueryExtTargets       = "ext_targets"
	// Kernel kfunc FUNC_PROTO and syscall argument types from tracefs or
	// __do_sys_ BTF are privilege-independent queries.
	QueryKfuncProtos = "kfunc_protos"
	QuerySyscallArgs = "syscall_args"
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
