package requirements

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Recorded caps carry kernel answers, loader declarations and probe UID/CapEff
// (docs/requirements_format.md section 10). All optional interfaces exist, but
// QuerySet reports unrecorded queries as unavailable. A missing key in a recorded
// query is an error, never implicit true.

// RecordedFormat identifies caps.json's format.
const RecordedFormat = "ebpf-caps 20" // the sleepable_types query (program type x attach type pair loadable with BPF_F_SLEEPABLE).

// Format 19 introduced the helper_target query; keep its minimum unchanged.
const recordedFormatHelperTarget = "ebpf-caps 19"

const recordedFormatNetkit = "ebpf-caps 18" // direction-specific netkit link queries.

// Format 17 introduced arena loader declarations; keep their minimum unchanged.
const recordedFormatArena = "ebpf-caps 17"

// The kstruct_size query came one format before the arena loader keys.
const recordedFormatKStructSize = "ebpf-caps 16"

// The func_ret query came one format before kstruct_size.
const recordedFormatFuncRet = "ebpf-caps 15"

// The ksym_vars / kconfig / btf_presence queries and the typed_ksym / kconfig
// loader keys came one format before func_ret.
const recordedFormatExternDecls = "ebpf-caps 14"

// The loader key hidden_data_vars came one format before the guard additions.
const recordedFormatHiddenDataVars = "ebpf-caps 13"

// The fib_lookup_flags query came one format before hidden_data_vars.
const recordedFormatFibFlags = "ebpf-caps 12"

// The enum_values query came one format before fib_lookup_flags (named by the query, not the number).
const recordedFormatEnumValues = "ebpf-caps 11"

// Format 10 added the separate DWARF query.
const recordedFormatV10 = "ebpf-caps 10"

const recordedFormatV9 = "ebpf-caps 9"

// Format 8 introduced four loader keys and prototype/syscall queries.
const recordedFormatV8 = "ebpf-caps 8"

// Format 7 remains readable but cannot carry those format-8 additions
// (caps_key_newer_format). Missing loader declarations are Unknown, except
// sockmap_attach uses the strict link decision.
const recordedFormatV7 = "ebpf-caps 7"

// Format 6 splits privileged queries like format 7 but cannot carry
// usdt_attach. Reject intermediate writers that incorrectly labeled this key
// as format 6; do not redefine the format accepted by earlier released readers.
const recordedFormatV6 = "ebpf-caps 6"

// Format 5 stores all queries together; the query table identifies privileges.
const recordedFormatV5 = "ebpf-caps 5"

// Format 4 lacks tracepoint_fields/struct_ops_members/ext_targets, yielding
// their blocking Unknown outcomes.
const recordedFormatV4 = "ebpf-caps 4"

// Format 3 lacks attach_types/attach_targets/ctx_access (nonblocking Unknown).
const recordedFormatV3 = "ebpf-caps 3"

// Format 2 lacks func_args; fentry pointer-argument objects block with farg_unknown.
const recordedFormatV2 = "ebpf-caps 2"

// ProbedAs records effective probe privileges; answers can depend on them
// (docs/nonroot.md).
type ProbedAs struct {
	UID    int    `json:"uid"`
	CapEff string `json:"cap_eff"` // Hexadecimal CapEff from /proc/self/status.
}

// Answer contains exactly one query outcome.
type Answer struct {
	Value   *bool     `json:"value,omitempty"`   // Boolean answer.
	Unknown string    `json:"unknown,omitempty"` // Indeterminate reason, wrapping ErrUnknown.
	Error   string    `json:"error,omitempty"`   // Query error distinct from Unknown.
	Diffs   *[]string `json:"diffs,omitempty"`   // Mismatch text; empty means a match.
	Text    *string   `json:"text,omitempty"`    // Text value, e.g. architecture.
	File    string    `json:"file,omitempty"`    // Binary path relative to the caps.json directory.
}

// LoaderJSON is the recorded loader declaration.
type LoaderJSON struct {
	Name                    string            `json:"name"`
	KprobeAliasPrefix       map[string]string `json:"kprobe_alias_prefix"`
	UprobeReopensPath       bool              `json:"uprobe_reopens_path"`
	COREPoisonsMissingField bool              `json:"core_poisons_missing_field"`
	BTFRewrite              map[string]string `json:"btf_rewrite"` // Feature -> rewrite/keep.
	// USDT attach is none/plain/ref_ctr; omitted means blocking
	// usdt_loader_unknown, including old recordings and undeclared loaders.
	USDTAttach string `json:"usdt_attach,omitempty"`
	// Since format 8: sockmap link/prog_attach, lsm_cgroup/fsession none/btf_id,
	// ksyscall none/prefix. Omitted sockmap uses link; other omitted values
	// produce blocking *_loader_unknown.
	SockmapAttach  string `json:"sockmap_attach,omitempty"`
	LSMCgroupLoad  string `json:"lsm_cgroup_load,omitempty"`
	FsessionLoad   string `json:"fsession_load,omitempty"`
	KsyscallAttach string `json:"ksyscall_attach,omitempty"`
	// Since format 13: hidden_data_vars no_mmap / mmap; omitted
	// produces blocking datakptr_loader_unknown.
	HiddenDataVars string `json:"hidden_data_vars,omitempty"`
	// Since format 14: typed_ksym btf_id / kallsyms_addr and kconfig
	// weak_zero / strong_only; omitted produces blocking
	// typed_ksym_loader_unknown / kconfig_loader_unknown.
	TypedKsym string `json:"typed_ksym,omitempty"`
	Kconfig   string `json:"kconfig,omitempty"`
	// Since format 17: arena_cast preserve / corrupt and arena_premmap
	// create_then_mmap / none; omitted produces blocking arena_loader_unknown
	// (unless the other key is a definite corrupt / none — arena_loader).
	ArenaCast    string `json:"arena_cast,omitempty"`
	ArenaPremmap string `json:"arena_premmap,omitempty"`
}

// arenaDeclKeys are the format-17 declaration keys.
func (l *LoaderJSON) arenaDeclKeys() [][2]string {
	return [][2]string{{"arena_cast", l.ArenaCast}, {"arena_premmap", l.ArenaPremmap}}
}

// externDeclKeys are the format-14 declaration keys.
func (l *LoaderJSON) externDeclKeys() [][2]string {
	return [][2]string{{"typed_ksym", l.TypedKsym}, {"kconfig", l.Kconfig}}
}

// typedFamilyDeclKeys follows specification section 13 declaration-key order.
func (l *LoaderJSON) typedFamilyDeclKeys() [][2]string {
	return [][2]string{{"sockmap_attach", l.SockmapAttach}, {"lsm_cgroup_load", l.LSMCgroupLoad}, {"fsession_load", l.FsessionLoad}, {"ksyscall_attach", l.KsyscallAttach}}
}

// Validate checks USDT and the four newer declaration-field spellings.
func (l *LoaderJSON) Validate() error {
	if !ValidUSDTAttach(l.USDTAttach) {
		return fmt.Errorf("loader %q: usdt_attach %q, want %q, %q or %q (or no key — unknown)", l.Name, l.USDTAttach, USDTAttachNone, USDTAttachPlain, USDTAttachRefCtr)
	}
	for _, kv := range l.typedFamilyDeclKeys() {
		if !validDeclValue(kv[0], kv[1]) {
			return fmt.Errorf("loader %q: %s %q is not a known value (or no key — not declared)", l.Name, kv[0], kv[1])
		}
	}
	if !validDeclValue("hidden_data_vars", l.HiddenDataVars) {
		return fmt.Errorf("loader %q: hidden_data_vars %q is not a known value (or no key — not declared)", l.Name, l.HiddenDataVars)
	}
	for _, kv := range l.externDeclKeys() {
		if !validDeclValue(kv[0], kv[1]) {
			return fmt.Errorf("loader %q: %s %q is not a known value (or no key — not declared)", l.Name, kv[0], kv[1])
		}
	}
	for _, kv := range l.arenaDeclKeys() {
		if !validDeclValue(kv[0], kv[1]) {
			return fmt.Errorf("loader %q: %s %q is not a known value (or no key — not declared)", l.Name, kv[0], kv[1])
		}
	}
	return nil
}

// Decl converts the recorded declaration to its Go form.
func (l *LoaderJSON) Decl() LoaderDecl {
	return LoaderDecl{Name: l.Name, KprobeAliasPrefix: l.KprobeAliasPrefix, UprobeReopensPath: l.UprobeReopensPath,
		COREPoisonsMissingField: l.COREPoisonsMissingField, BTFRewrite: l.BTFRewrite, USDTAttach: l.USDTAttach,
		SockmapAttach: l.SockmapAttach, LSMCgroupLoad: l.LSMCgroupLoad, FsessionLoad: l.FsessionLoad, KsyscallAttach: l.KsyscallAttach,
		HiddenDataVars: l.HiddenDataVars, TypedKsym: l.TypedKsym, Kconfig: l.Kconfig, ArenaCast: l.ArenaCast, ArenaPremmap: l.ArenaPremmap}
}

// LoaderJSONOf converts a declaration to its JSON form.
func LoaderJSONOf(d LoaderDecl) *LoaderJSON {
	return &LoaderJSON{Name: d.Name, KprobeAliasPrefix: d.KprobeAliasPrefix, UprobeReopensPath: d.UprobeReopensPath,
		COREPoisonsMissingField: d.COREPoisonsMissingField, BTFRewrite: d.BTFRewrite, USDTAttach: d.USDTAttach,
		SockmapAttach: d.SockmapAttach, LSMCgroupLoad: d.LSMCgroupLoad, FsessionLoad: d.FsessionLoad, KsyscallAttach: d.KsyscallAttach,
		HiddenDataVars: d.HiddenDataVars, TypedKsym: d.TypedKsym, Kconfig: d.Kconfig, ArenaCast: d.ArenaCast, ArenaPremmap: d.ArenaPremmap}
}

// ForFormat retains only declaration keys that format can carry: <=7 lacks
// the four newer keys, and <=6 also lacks usdt_attach.
func (l LoaderJSON) ForFormat(format string) LoaderJSON {
	if format != RecordedFormat && format != recordedFormatHelperTarget && format != recordedFormatNetkit && format != recordedFormatArena { // arena_cast / arena_premmap are new in format 17.
		l.ArenaCast, l.ArenaPremmap = "", ""
	}
	if format != RecordedFormat && format != recordedFormatHelperTarget && format != recordedFormatNetkit && format != recordedFormatArena && format != recordedFormatKStructSize && format != recordedFormatFuncRet && format != recordedFormatExternDecls { // typed_ksym / kconfig are new in format 14.
		l.TypedKsym, l.Kconfig = "", ""
	}
	if format != RecordedFormat && format != recordedFormatHelperTarget && format != recordedFormatNetkit && format != recordedFormatArena && format != recordedFormatKStructSize && format != recordedFormatFuncRet && format != recordedFormatExternDecls && format != recordedFormatHiddenDataVars { // hidden_data_vars is new in format 13.
		l.HiddenDataVars = ""
	}
	if format != RecordedFormat && format != recordedFormatHelperTarget && format != recordedFormatNetkit && format != recordedFormatArena && format != recordedFormatKStructSize && format != recordedFormatFuncRet && format != recordedFormatExternDecls && format != recordedFormatHiddenDataVars && format != recordedFormatFibFlags && format != recordedFormatEnumValues && format != recordedFormatV10 && format != recordedFormatV9 && format != recordedFormatV8 {
		l.SockmapAttach, l.LSMCgroupLoad, l.FsessionLoad, l.KsyscallAttach = "", "", "", ""
		if format != recordedFormatV7 {
			l.USDTAttach = ""
		}
	}
	return l
}

// RecordedCaps stores caps.json. After reading, Queries combines both query
// classes; MarshalJSON separates privilege-dependent queries for formats that
// support privileged_queries.
type RecordedCaps struct {
	Format            string                       `json:"format"`
	ProbedAs          *ProbedAs                    `json:"probed_as,omitempty"`
	LoaderD           *LoaderJSON                  `json:"loader"`
	Queries           map[string]map[string]Answer `json:"queries"`
	PrivilegedQueries map[string]map[string]Answer `json:"privileged_queries,omitempty"` // Parse-only storage, merged into Queries then cleared.
	dir               string
	scope             *loadScope // Intended load privileges supplied by ForLoad.
}

// recordedJSON avoids recursive MarshalJSON calls by having no methods.
type recordedJSON struct {
	Format            string                       `json:"format"`
	ProbedAs          *ProbedAs                    `json:"probed_as,omitempty"`
	LoaderD           *LoaderJSON                  `json:"loader"`
	Queries           map[string]map[string]Answer `json:"queries"`
	PrivilegedQueries map[string]map[string]Answer `json:"privileged_queries,omitempty"`
}

// splitsPrivileged identifies formats with a separate privileged_queries map.
func splitsPrivileged(format string) bool {
	return format == RecordedFormat || format == recordedFormatHelperTarget || format == recordedFormatNetkit || format == recordedFormatArena || format == recordedFormatKStructSize || format == recordedFormatFuncRet || format == recordedFormatExternDecls || format == recordedFormatHiddenDataVars || format == recordedFormatFibFlags || format == recordedFormatEnumValues || format == recordedFormatV10 || format == recordedFormatV9 || format == recordedFormatV8 || format == recordedFormatV7 || format == recordedFormatV6
}

// MarshalJSON splits privilege-dependent answers for split-capable formats;
// formats <=5 use queries alone.
func (c RecordedCaps) MarshalJSON() ([]byte, error) {
	out := recordedJSON{Format: c.Format, ProbedAs: c.ProbedAs, LoaderD: c.LoaderD, Queries: map[string]map[string]Answer{}}
	for q, m := range c.Queries {
		if splitsPrivileged(c.Format) && PrivilegeDependent(q) {
			if out.PrivilegedQueries == nil {
				out.PrivilegedQueries = map[string]map[string]Answer{}
			}
			out.PrivilegedQueries[q] = m
			continue
		}
		out.Queries[q] = m
	}
	for q, m := range c.PrivilegedQueries { // Parse-only value, normally nil.
		if out.PrivilegedQueries == nil {
			out.PrivilegedQueries = map[string]map[string]Answer{}
		}
		out.PrivilegedQueries[q] = m
	}
	return json.Marshal(out)
}

// ReadRecordedCaps validates format, loader declaration, the three required
// queries and all query names while reading caps.json.
func ReadRecordedCaps(path string) (*RecordedCaps, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := ParseRecordedCaps(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.dir = filepath.Dir(path)
	return c, nil
}

// knownQueries enumerates caps.json query keys.
var knownQueries = []string{QueryHelperTarget, QueryProgType, QueryHelper, QueryMapType, QueryTCX, QueryNetkit, QueryFuncSig, QueryFunc, QueryTracepoint, QueryKFields,
	QueryBTFFeature, QueryArgTag, QueryArch, QueryStructField, QueryKernelSym, QueryFuncParam, QueryUprobeBin, QueryMapField, QueryNullableArgs, QueryTracingHelper,
	QueryFuncArgs,                                      // Format 3.
	QueryAttachType, QueryAttachTarget, QueryCtxAccess, // Format 4.
	QueryTracepointFields, QueryStructOpsMembers, QueryExtTargets, // Format 5.
	QueryKfuncProtos, QuerySyscallArgs, // Format 8.
	QueryKfuncLoad, QueryTracepointBuffer, QueryUprobeDebug, // Formats 9 and 10.
	QueryEnumValues,                               // Format 11.
	QueryFibLookupFlags,                           // Format 12.
	QueryKsymVars, QueryKconfig, QueryBTFPresence, // Format 14.
	QueryFuncRet,     // Format 15.
	QueryKStructSize, // Format 16 (format 17 adds loader keys only; format 18 is netkit).
	QuerySleepable}   // Format 19.

// ParseRecordedCaps parses caps bytes; relative binary paths use the current
// working directory.
func ParseRecordedCaps(data []byte) (*RecordedCaps, error) {
	// Read format permissively first: unsupported old formats can contain
	// unknown keys that must not hide the format diagnostic.
	var head struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(data, &head); err == nil && head.Format == "ebpf-caps 1" {
		return nil, fmt.Errorf("caps: format %q is no longer read (the loader's BTF rewrites moved from the query btf_rewrites to the loader declaration's btf_rewrite); record the caps again as %q", head.Format, RecordedFormat)
	}
	var c RecordedCaps
	// Check format after byte-level rules but before typed unknown_key/type
	// decoding, so a newer format is rejected by name rather than by its keys.
	if err := scanStrictJSON(data, &c); err != nil {
		return nil, fmt.Errorf("caps: %w", err)
	}
	if err := json.Unmarshal(data, &head); err == nil && !knownRecordedFormat(head.Format) {
		return nil, &CapsFormatError{Rule: CapsRuleFormatUnknown, Msg: fmt.Sprintf("caps: format %q, want %q (or %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q)",
			head.Format, RecordedFormat, recordedFormatHelperTarget, recordedFormatNetkit, recordedFormatArena, recordedFormatKStructSize, recordedFormatFuncRet, recordedFormatExternDecls, recordedFormatHiddenDataVars, recordedFormatFibFlags, recordedFormatEnumValues, recordedFormatV10, recordedFormatV9, recordedFormatV8, recordedFormatV7, recordedFormatV6, recordedFormatV5, recordedFormatV4, recordedFormatV3, recordedFormatV2)}
	}
	if err := DecodeStrictJSON(data, &c); err != nil { // Reject duplicate/case-mismatched keys, invalid UTF-8, trailing data and depth.
		return nil, fmt.Errorf("caps: %w", err)
	}
	if c.Format == "ebpf-caps 1" {
		return nil, fmt.Errorf("caps: format %q is no longer read (the loader's BTF rewrites moved from the query btf_rewrites to the loader declaration's btf_rewrite); record the caps again as %q", c.Format, RecordedFormat)
	}
	if err := checkRecordedSleepable(&c); err != nil {
		return nil, err
	}
	if err := checkRecordedNetkit(&c); err != nil {
		return nil, err
	}
	if err := checkRecordedHelperTargets(&c, data); err != nil {
		return nil, err
	}
	hasPrivilegeSplit := splitsPrivileged(c.Format) // Include readable formats 6, 7 and 8.
	hasTypedAttachQueries := hasPrivilegeSplit || c.Format == recordedFormatV5
	if !hasTypedAttachQueries && c.Format != recordedFormatV4 && c.Format != recordedFormatV3 && c.Format != recordedFormatV2 {
		return nil, &CapsFormatError{Rule: CapsRuleFormatUnknown, Msg: fmt.Sprintf("caps: format %q, want %q (or %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q / %q)", c.Format, RecordedFormat, recordedFormatHelperTarget, recordedFormatNetkit, recordedFormatArena, recordedFormatKStructSize, recordedFormatFuncRet, recordedFormatExternDecls, recordedFormatHiddenDataVars, recordedFormatFibFlags, recordedFormatEnumValues, recordedFormatV10, recordedFormatV9, recordedFormatV8, recordedFormatV7, recordedFormatV6, recordedFormatV5, recordedFormatV4, recordedFormatV3, recordedFormatV2)}
	}
	// usdt_attach requires caps format 7, just as func_args requires its own
	// minimum format; earlier records carrying it are invalid.
	if c.LoaderD != nil && c.LoaderD.USDTAttach != "" && c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars && c.Format != recordedFormatFibFlags && c.Format != recordedFormatEnumValues && c.Format != recordedFormatV10 && c.Format != recordedFormatV9 && c.Format != recordedFormatV8 && c.Format != recordedFormatV7 {
		return nil, keyNewerFormat("caps: loader key %q is new in %q, but the format is %q", "usdt_attach", recordedFormatV7, c.Format)
	}
	// hidden_data_vars requires caps format 13.
	if c.LoaderD != nil && c.LoaderD.HiddenDataVars != "" && c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars {
		return nil, keyNewerFormat("caps: loader key %q is new in %q, but the format is %q", "hidden_data_vars", recordedFormatHiddenDataVars, c.Format)
	}
	// typed_ksym / kconfig require caps format 14.
	if c.LoaderD != nil && c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls {
		for _, kv := range c.LoaderD.externDeclKeys() {
			if kv[1] != "" {
				return nil, keyNewerFormat("caps: loader key %q is new in %q, but the format is %q", kv[0], recordedFormatExternDecls, c.Format)
			}
		}
	}
	// arena_cast / arena_premmap require caps format 17.
	if c.LoaderD != nil && c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena {
		for _, kv := range c.LoaderD.arenaDeclKeys() {
			if kv[1] != "" {
				return nil, keyNewerFormat("caps: loader key %q is new in %q, but the format is %q", kv[0], recordedFormatArena, c.Format)
			}
		}
	}
	// The four newer loader keys require caps format 8.
	if c.LoaderD != nil && c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars && c.Format != recordedFormatFibFlags && c.Format != recordedFormatEnumValues && c.Format != recordedFormatV10 && c.Format != recordedFormatV9 && c.Format != recordedFormatV8 {
		for _, kv := range c.LoaderD.typedFamilyDeclKeys() {
			if kv[1] != "" {
				return nil, keyNewerFormat("caps: loader key %q is new in %q, but the format is %q", kv[0], recordedFormatV8, c.Format)
			}
		}
	}
	// Name a new query's minimum-format violation before checking placement.
	// Do not raise old queries' meanings to format 9.
	if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars && c.Format != recordedFormatFibFlags && c.Format != recordedFormatEnumValues && c.Format != recordedFormatV10 && c.Format != recordedFormatV9 {
		for _, q := range []string{QueryKfuncLoad, QueryTracepointBuffer} {
			_, plain := c.Queries[q]
			_, privileged := c.PrivilegedQueries[q]
			if plain || privileged {
				return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", q, recordedFormatV9, c.Format)
			}
		}
	}
	if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars && c.Format != recordedFormatFibFlags && c.Format != recordedFormatEnumValues && c.Format != recordedFormatV10 {
		_, plain := c.Queries[QueryUprobeDebug]
		_, privileged := c.PrivilegedQueries[QueryUprobeDebug]
		if plain || privileged {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryUprobeDebug, recordedFormatV10, c.Format)
		}
	}
	// enum_values requires format 11 (or later).
	if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars && c.Format != recordedFormatFibFlags && c.Format != recordedFormatEnumValues {
		_, plain := c.Queries[QueryEnumValues]
		_, privileged := c.PrivilegedQueries[QueryEnumValues]
		if plain || privileged {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryEnumValues, recordedFormatEnumValues, c.Format)
		}
	}
	// fib_lookup_flags is new in format 12.
	if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars && c.Format != recordedFormatFibFlags {
		_, plain := c.Queries[QueryFibLookupFlags]
		_, privileged := c.PrivilegedQueries[QueryFibLookupFlags]
		if plain || privileged {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryFibLookupFlags, recordedFormatFibFlags, c.Format)
		}
	}
	// ksym_vars / kconfig / btf_presence are new in format 14.
	if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls {
		for _, q := range []string{QueryKsymVars, QueryKconfig, QueryBTFPresence} {
			_, plain := c.Queries[q]
			_, privileged := c.PrivilegedQueries[q]
			if plain || privileged {
				return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", q, recordedFormatExternDecls, c.Format)
			}
		}
	}
	// func_ret is new in format 15.
	if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet {
		_, plain := c.Queries[QueryFuncRet]
		_, privileged := c.PrivilegedQueries[QueryFuncRet]
		if plain || privileged {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryFuncRet, recordedFormatFuncRet, c.Format)
		}
	}
	// kstruct_size is new in format 16.
	if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize {
		_, plain := c.Queries[QueryKStructSize]
		_, privileged := c.PrivilegedQueries[QueryKStructSize]
		if plain || privileged {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryKStructSize, recordedFormatKStructSize, c.Format)
		}
	}
	// Since format 6, dependent queries belong in privileged_queries and
	// independent queries in queries.
	if c.PrivilegedQueries != nil && !hasPrivilegeSplit {
		return nil, keyNewerFormat("caps: privileged_queries is new in %q, but the format is %q", recordedFormatV6, c.Format)
	}
	if hasPrivilegeSplit {
		// Name the first misplaced query in sorted order, not random map order.
		// Diagnostics identify the format and are copied byte-for-byte by bml.
		for _, q := range sortedQueryNames(c.Queries) {
			if PrivilegeDependent(q) {
				return nil, fmt.Errorf("caps: query %q depends on the probing privilege — %q keeps it under privileged_queries", q, c.Format)
			}
		}
		for _, q := range sortedQueryNames(c.PrivilegedQueries) {
			if !PrivilegeDependent(q) {
				return nil, fmt.Errorf("caps: query %q does not depend on the probing privilege — %q keeps it under queries", q, c.Format)
			}
		}
		for q, m := range c.PrivilegedQueries {
			if c.Queries == nil {
				c.Queries = map[string]map[string]Answer{}
			}
			c.Queries[q] = m
		}
		c.PrivilegedQueries = nil
	}
	if _, ok := c.Queries[QueryFuncArgs]; ok && c.Format == recordedFormatV2 {
		return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryFuncArgs, recordedFormatV3, c.Format)
	}
	// attach_types/attach_targets/ctx_access require format 4.
	for _, q := range []string{QueryAttachType, QueryAttachTarget, QueryCtxAccess} {
		if _, ok := c.Queries[q]; ok && !hasTypedAttachQueries && c.Format != recordedFormatV4 {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", q, recordedFormatV4, c.Format)
		}
	}
	// tracepoint_fields/struct_ops_members/ext_targets require format 5.
	for _, q := range []string{QueryTracepointFields, QueryStructOpsMembers, QueryExtTargets} {
		if _, ok := c.Queries[q]; ok && !hasTypedAttachQueries {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", q, recordedFormatV5, c.Format)
		}
	}
	// kfunc_protos/syscall_args require format 8.
	for _, q := range []string{QueryKfuncProtos, QuerySyscallArgs} {
		if _, ok := c.Queries[q]; ok && c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget && c.Format != recordedFormatNetkit && c.Format != recordedFormatArena && c.Format != recordedFormatKStructSize && c.Format != recordedFormatFuncRet && c.Format != recordedFormatExternDecls && c.Format != recordedFormatHiddenDataVars && c.Format != recordedFormatFibFlags && c.Format != recordedFormatEnumValues && c.Format != recordedFormatV10 && c.Format != recordedFormatV9 && c.Format != recordedFormatV8 {
			return nil, keyNewerFormat("caps: query %q is new in %q, but the format is %q", q, recordedFormatV8, c.Format)
		}
	}
	if c.LoaderD == nil || c.LoaderD.Name == "" {
		return nil, fmt.Errorf("caps: no loader declaration (a recorded target is judged for a named loader)")
	}
	if err := c.LoaderD.Validate(); err != nil {
		return nil, fmt.Errorf("caps: %w", err)
	}
	known := map[string]bool{}
	for _, q := range knownQueries {
		known[q] = true
	}
	// Sort names and keys to report the first unknown query or malformed answer
	// deterministically.
	for _, q := range sortedQueryNames(c.Queries) {
		if !known[q] {
			return nil, fmt.Errorf("caps: unknown query %q", q)
		}
	}
	for _, q := range []string{QueryProgType, QueryHelper, QueryMapType} {
		if _, ok := c.Queries[q]; !ok {
			return nil, fmt.Errorf("caps: query %q is required", q)
		}
	}
	for _, q := range sortedQueryNames(c.Queries) {
		m := c.Queries[q]
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			a := m[k]
			n := 0
			for _, set := range []bool{a.Value != nil, a.Unknown != "", a.Error != "", a.Diffs != nil, a.Text != nil, a.File != ""} {
				if set {
					n++
				}
			}
			if n != 1 {
				return nil, fmt.Errorf("caps: %s[%q]: an answer has exactly one of value / unknown / error / diffs / text / rewrites / file", q, k)
			}
			if q == QueryUprobeDebug && a.File == "" && a.Unknown == "" && a.Error == "" {
				return nil, fmt.Errorf("caps: %s[%q]: an answer has exactly one of file / unknown / error", q, k)
			}
		}
	}
	return &c, nil
}

// HasQuery checks recorded query availability. If ForLoad changes privileges
// and supplies re-probe caps, dependent-query availability comes from them.
func (c *RecordedCaps) HasQuery(q string) bool {
	if q == QueryHelperTarget {
		if r, err, use := c.helperTargetPrivilege(); !use && err == nil {
			return reprobeHas(r, q)
		}
	}
	if r, err, use := c.privileged(q); !use && err == nil {
		return reprobeHas(r, q)
	}
	_, ok := c.Queries[q]
	return ok
}

// Loader returns the recorded declaration.
func (c *RecordedCaps) Loader() LoaderDecl {
	return c.LoaderD.Decl() // Include USDT attach behavior.
}

type unknownErr string

func (e unknownErr) Error() string        { return string(e) }
func (e unknownErr) Is(target error) bool { return target == ErrUnknown }

// answer returns query q/key, rejecting an unrecorded key.
func (c *RecordedCaps) answer(q, key string) (Answer, error) {
	a, ok := c.Queries[q][key]
	if !ok {
		return Answer{}, fmt.Errorf("recorded caps: no answer for %s %q", q, key)
	}
	if a.Unknown != "" {
		return a, unknownErr(a.Unknown)
	}
	if a.Error != "" {
		return a, errors.New(a.Error)
	}
	return a, nil
}

func (c *RecordedCaps) boolean(q, key string) (bool, error) {
	a, err := c.answer(q, key)
	if err != nil {
		return false, err
	}
	if a.Value == nil {
		return false, fmt.Errorf("recorded caps: %s %q is not a value answer", q, key)
	}
	return *a.Value, nil
}

func (c *RecordedCaps) diffs(q, key string) ([]string, error) {
	a, err := c.answer(q, key)
	if err != nil {
		return nil, err
	}
	if a.Diffs == nil {
		return nil, fmt.Errorf("recorded caps: %s %q is not a diffs answer", q, key)
	}
	return *a.Diffs, nil
}

// Keys follow specification section 10. HasProgType uses the program type name.
// Privilege-dependent methods call privileged first, redirecting to re-probe
// caps or Unknown when ForLoad privileges differ.
func (c *RecordedCaps) HasProgType(name string, id int64) (bool, error) {
	if r, err, use := c.privileged(QueryProgType); !use {
		if err != nil {
			return false, err
		}
		return r.HasProgType(name, id)
	}
	return c.boolean(QueryProgType, name)
}

// HasHelper key: <program-type>/<helper>.
func (c *RecordedCaps) HasHelper(pt string, ptID int64, h string, hID int64) (bool, error) {
	if r, err, use := c.privileged(QueryHelper); !use {
		if err != nil {
			return false, err
		}
		return r.HasHelper(pt, ptID, h, hID)
	}
	return c.boolean(QueryHelper, pt+"/"+h)
}

// HasTracingHelper key: <attach-type>/<helper>.
func (c *RecordedCaps) HasTracingHelper(at, h string, hID int64) (bool, error) {
	if r, err, use := c.privileged(QueryTracingHelper); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(TracingHelperCaps); ok {
			return t.HasTracingHelper(at, h, hID)
		}
		return false, noReprobe(QueryTracingHelper)
	}
	return c.boolean(QueryTracingHelper, at+"/"+h)
}

// HasMapType key: map type name.
func (c *RecordedCaps) HasMapType(name string, id int64) (bool, error) {
	if r, err, use := c.privileged(QueryMapType); !use {
		if err != nil {
			return false, err
		}
		return r.HasMapType(name, id)
	}
	return c.boolean(QueryMapType, name)
}

// HasTCX key is empty, once per target.
func (c *RecordedCaps) HasTCX() (bool, error) {
	if r, err, use := c.privileged(QueryTCX); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(TCXCaps); ok {
			return t.HasTCX()
		}
		return false, noReprobe(QueryTCX)
	}
	return c.boolean(QueryTCX, "")
}

// CheckFuncSig key: <function>/<nargs>/<ret>.
func (c *RecordedCaps) CheckFuncSig(name string, nargs int, ret string) ([]string, error) {
	return c.diffs(QueryFuncSig, name+"/"+strconv.Itoa(nargs)+"/"+ret)
}

// CheckFuncRet key: <function>/<ret>.
func (c *RecordedCaps) CheckFuncRet(name, ret string) ([]string, error) {
	return c.diffs(QueryFuncRet, name+"/"+ret)
}

// CheckFunc key: function name.
func (c *RecordedCaps) CheckFunc(name string) ([]string, error) { return c.diffs(QueryFunc, name) }

// CheckTracepoint key: <tracepoint>(<struct>,...).
func (c *RecordedCaps) CheckTracepoint(name string, args []string) ([]string, error) {
	return c.diffs(QueryTracepoint, name+"("+strings.Join(args, ",")+")")
}

// CheckFuncArgs key: <function>(<struct|->,...).
func (c *RecordedCaps) CheckFuncArgs(name string, args []string) ([]string, error) {
	return c.diffs(QueryFuncArgs, name+"("+strings.Join(args, ",")+")")
}

// CheckKFields uses one <program> <struct>.<field> <type> key per field,
// joining mismatch text in field order.
func (c *RecordedCaps) CheckKFields(kf []KField) ([]string, error) {
	var out []string
	for _, k := range kf {
		d, err := c.diffs(QueryKFields, k.Program+" "+k.Struct+"."+k.Field+" "+k.Type)
		if err != nil {
			return nil, err
		}
		out = append(out, d...)
	}
	return out, nil
}

// HasBTFFeature key: feature name.
func (c *RecordedCaps) HasBTFFeature(f string) (bool, error) {
	if r, err, use := c.privileged(QueryBTFFeature); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(BTFFeatureCaps); ok {
			return t.HasBTFFeature(f)
		}
		return false, noReprobe(QueryBTFFeature)
	}
	return c.boolean(QueryBTFFeature, f)
}

// HasArgTagSemantics key: <program-type>/<tag>/<class>.
func (c *RecordedCaps) HasArgTagSemantics(pt string, ptID int64, tag, class string) (bool, error) {
	if r, err, use := c.privileged(QueryArgTag); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(ArgTagCaps); ok {
			return t.HasArgTagSemantics(pt, ptID, tag, class)
		}
		return false, noReprobe(QueryArgTag)
	}
	return c.boolean(QueryArgTag, pt+"/"+tag+"/"+class)
}

// Arch key is empty.
func (c *RecordedCaps) Arch() (string, error) {
	a, err := c.answer(QueryArch, "")
	if err != nil {
		return "", err
	}
	if a.Text == nil {
		return "", fmt.Errorf("recorded caps: arch is not a text answer")
	}
	return *a.Text, nil
}

// CheckStructField key: <struct>.<field>/<offset>/<size>.
func (c *RecordedCaps) CheckStructField(st, field string, off, size int) ([]string, error) {
	return c.diffs(QueryStructField, st+"."+field+"/"+strconv.Itoa(off)+"/"+strconv.Itoa(size))
}

// HasKernelSymbol key: symbol name.
func (c *RecordedCaps) HasKernelSymbol(name string) (bool, error) {
	return c.boolean(QueryKernelSym, name)
}

// CheckFuncParam key: <function>/<n>/<type>.
func (c *RecordedCaps) CheckFuncParam(name string, n int, typ string) ([]string, error) {
	return c.diffs(QueryFuncParam, name+"/"+strconv.Itoa(n)+"/"+typ)
}

// UprobeBinary key is the program symbol; answer paths are absolute or
// relative to caps.json's directory.
func (c *RecordedCaps) UprobeBinary(program string) (io.ReaderAt, error) {
	a, err := c.answer(QueryUprobeBin, program)
	if err != nil {
		return nil, err
	}
	if a.File == "" {
		return nil, fmt.Errorf("recorded caps: uprobe_binary %q is not a file answer", program)
	}
	path := a.File
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.dir, path)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return bytes.NewReader(data), nil
}

// UprobeDebugFile uses caps.json's directory, independent of the invoking cwd.
func (c *RecordedCaps) UprobeDebugFile(program string, id []byte) (io.ReaderAt, error) {
	key := UprobeDebugKey(program, id)
	a, err := c.answer(QueryUprobeDebug, key)
	if err != nil {
		return nil, err
	}
	if a.File == "" {
		return nil, fmt.Errorf("recorded caps: uprobe_debug %q is not a file answer", key)
	}
	path := a.File
	if !filepath.IsAbs(path) {
		path = filepath.Join(c.dir, path)
	}
	return ReadUprobeDebugFile(path)
}

// AllowsMapField key: <program-type>/<field>.
func (c *RecordedCaps) AllowsMapField(pt string, ptID int64, field string) (bool, error) {
	if r, err, use := c.privileged(QueryMapField); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(MapFieldPolicy); ok {
			return t.AllowsMapField(pt, ptID, field)
		}
		return false, noReprobe(QueryMapField)
	}
	return c.boolean(QueryMapField, pt+"/"+field)
}

// MarksNullableTPArgs key is empty.
func (c *RecordedCaps) MarksNullableTPArgs() (bool, error) {
	if r, err, use := c.privileged(QueryNullableArgs); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(NullableArgCaps); ok {
			return t.MarksNullableTPArgs()
		}
		return false, noReprobe(QueryNullableArgs)
	}
	return c.boolean(QueryNullableArgs, "")
}

// Sorted query-key inventory for tests and diagnostics.
func (c *RecordedCaps) QueryNames() []string {
	var out []string
	for q := range c.Queries {
		out = append(out, q)
	}
	sort.Strings(out)
	return out
}

// HasAttachType key: <program-type>/<attach-type>.
func (c *RecordedCaps) HasAttachType(pt string, ptID int64, at string) (bool, error) {
	if r, err, use := c.privileged(QueryAttachType); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(AttachTypeCaps); ok {
			return t.HasAttachType(pt, ptID, at)
		}
		return false, noReprobe(QueryAttachType)
	}
	return c.boolean(QueryAttachType, pt+"/"+at)
}

// HasAttachTarget key: <attach-type>/<kind>:<value>.
func (c *RecordedCaps) HasAttachTarget(at, kind, value string) (bool, error) {
	return c.boolean(QueryAttachTarget, at+"/"+kind+":"+value)
}

// AllowsCtxAccess key: <program-type>/<attach-type>/<struct>.<field>/<r|w>/<bytes>.
func (c *RecordedCaps) AllowsCtxAccess(pt string, ptID int64, at, st, field, mode string, bytes int) (bool, error) {
	if r, err, use := c.privileged(QueryCtxAccess); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(CtxAccessCaps); ok {
			return t.AllowsCtxAccess(pt, ptID, at, st, field, mode, bytes)
		}
		return false, noReprobe(QueryCtxAccess)
	}
	return c.boolean(QueryCtxAccess, pt+"/"+at+"/"+st+"."+field+"/"+mode+"/"+strconv.Itoa(bytes))
}

// HasFibLookupFlags key: <program-type>/<program-type-id>/<mask>. Only
// the exact three-part key answers; another ID or mask is never borrowed.
func (c *RecordedCaps) HasFibLookupFlags(pt string, ptID int64, mask uint32) (bool, error) {
	if r, err, use := c.privileged(QueryFibLookupFlags); !use {
		if err != nil {
			return false, err
		}
		if t, ok := r.(FibLookupFlagsCaps); ok {
			return t.HasFibLookupFlags(pt, ptID, mask)
		}
		return false, noReprobe(QueryFibLookupFlags)
	}
	// Only the exact three-part key answers (another ID or
	// mask is never borrowed). A missing key follows the common rule of answer —
	// the record does not cover the ELF's question, a precheck error (not Unmet).
	return c.boolean(QueryFibLookupFlags, FibLookupFlagsKey(pt, ptID, mask))
}

// CheckTracepointField key: <category>/<event>/<field>/<offset>/<bytes>/<i|u>.
func (c *RecordedCaps) CheckTracepointField(event, field string, offset, bytes int, sign string) ([]string, error) {
	key := TPFieldKey(event, field, offset, bytes, sign)
	if _, ok := c.Queries[QueryTracepointFields][key]; !ok && (sign == "strptr" || sign == "strarray" || validKFieldByteArray(sign)) {
		return nil, unknownErr("recorded caps: no typed tracepoint field answer for " + key)
	}
	return c.diffs(QueryTracepointFields, key)
}

// CheckStructOpsMember key: <struct>.<member>/<nargs>/<ret>(<args>).
func (c *RecordedCaps) CheckStructOpsMember(strct, member string, nargs int, ret string, args []string) ([]string, error) {
	return c.diffs(QueryStructOpsMembers, StructOpsKey(strct, member, nargs, ret, args))
}

// CheckExtTarget key: <program>/<function>/<nargs>/<ret>(<args>). Recorder
// writes Unknown because replacements are loader inputs; only hand-authored
// caps, such as corpus cases, carry concrete answers.
func (c *RecordedCaps) CheckExtTarget(program, fn string, nargs int, ret string, args []string) ([]string, error) {
	return c.diffs(QueryExtTargets, ExtTargetKey(program, fn, nargs, ret, args))
}

// CheckKfunc key: <name>/<ret>(<arg>,...), as in KfuncKey.
func (c *RecordedCaps) CheckKfunc(name, ret string, args []string) ([]string, error) {
	return c.diffs(QueryKfuncProtos, KfuncKey(name, ret, args))
}

// CheckSyscallArg key: <syscall>/<n>/<type>, as in SysargKey.
func (c *RecordedCaps) CheckSyscallArg(name string, n int, typ string) ([]string, error) {
	if typ == "strptr" || typ == "strarray" {
		if _, ok := c.Queries[QuerySyscallArgs][SysargKey(name, n, typ)]; !ok {
			return nil, unknownErr("no recorded syscall string argument answer")
		}
	}
	return c.diffs(QuerySyscallArgs, SysargKey(name, n, typ))
}

func (c *RecordedCaps) HasKfuncLoad(profile KfuncProfile, name, ret string, args []string) (bool, error) {
	if r, err, use := c.privileged(QueryKfuncLoad); !use {
		if err != nil {
			return false, err
		}
		if !reprobeHas(r, QueryKfuncLoad) {
			return false, noReprobe(QueryKfuncLoad)
		}
		return r.(KernelKfuncLoadCaps).HasKfuncLoad(profile, name, ret, append([]string{}, args...))
	}
	return c.boolean(QueryKfuncLoad, KfuncLoadKey(profile, name, ret, args))
}

func (c *RecordedCaps) CheckTracepointBuffer(name, pointee string) ([]string, error) {
	return c.diffs(QueryTracepointBuffer, TracepointBufferKey(name, pointee))
}

// knownRecordedFormat identifies supported recorded formats. Format 1 gets
// its own unsupported-format diagnostic rather than being decoded.
func knownRecordedFormat(f string) bool {
	switch f {
	case RecordedFormat, recordedFormatHelperTarget, recordedFormatNetkit, recordedFormatArena, recordedFormatKStructSize, recordedFormatFuncRet, recordedFormatExternDecls, recordedFormatHiddenDataVars, recordedFormatFibFlags, recordedFormatEnumValues, recordedFormatV10, recordedFormatV9, recordedFormatV8, recordedFormatV7, recordedFormatV6, recordedFormatV5, recordedFormatV4, recordedFormatV3, recordedFormatV2, "ebpf-caps 1":
		return true
	}
	return false
}

// sortedQueryNames provides deterministic query ordering.
func sortedQueryNames(m map[string]map[string]Answer) []string {
	out := make([]string, 0, len(m))
	for q := range m {
		out = append(out, q)
	}
	sort.Strings(out)
	return out
}
