package requirements

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Format 13 adds kfunc signatures, ksyscall/sysarg, per-target mtargetarg,
// trace_lsm_cgroup/farg, BTF type_tag and loader declarations for sockmap,
// lsm_cgroup, fsession and ksyscall. See docs/requirements_format.md
// sections 3, 4, 5 and 8.
//
// KfuncAndSyscallMinVersion is the minimum for these new rows, typed families and type_tag.
const KfuncAndSyscallMinVersion = 13

// V13MinVersion is a format version, not a release version.
// Deprecated: use KfuncAndSyscallMinVersion.
const V13MinVersion = KfuncAndSyscallMinVersion

// isSyscallOrLSMCgroupAttachType identifies the typed families introduced in format 13.
func isSyscallOrLSMCgroupAttachType(t string) bool { return t == "trace_lsm_cgroup" || t == "ksyscall" }

// btfFeatureMinVersion is 13 for type_tag, 22 for enum, otherwise the
// BTF row minimum 5.
func btfFeatureMinVersion(f string) int {
	if f == "type_tag" {
		return KfuncAndSyscallMinVersion
	}
	if f == "enum" || f == "enum64" { // enum64: a 64-bit enum field's local type, a size-8 ENUM that readers treat as ENUM64
		return EnumKFieldMinVersion
	}
	return minVersion("btf")
}

// SyscallPrefixes matches libbpf arch_specific_syscall_pfx, checked against
// UAPI syscallpfx. ksyscall checks kallsyms for <prefix>sys_<name>.
var SyscallPrefixes = map[string]string{"x86_64": "__x64_"}

// SyscallMaxArgs bounds sysarg indices: at most six syscall arguments.
const SyscallMaxArgs = 6

// KfuncMaxArgs matches the five BPF argument registers (MAX_BPF_FUNC_REG_ARGS).
const KfuncMaxArgs = 5

// Kfunc describes kfunc <program> <name> <ret> <arg0> ... <argN-1>, checked
// against the target BTF FUNC_PROTO.
type Kfunc struct {
	Program, Name, Ret string
	Args               []string
}

// MTargetArg describes mtargetarg <program> <i> <n> <type>, argument n
// of multi-probe target i.
type MTargetArg struct {
	I, N int
	Type string
}

// validKfuncScalar accepts integer spellings i8..u64 and bool.
func validKfuncScalar(s string) bool { return validIntSpelling(s) || s == "bool" }

// validKfuncType accepts i8..u64/bool and ptr:<struct>, ptr:void, ptr:<integer>.
// Returns additionally allow void.
func validKfuncType(s string, ret bool) bool {
	if validKfuncScalar(s) || (ret && s == "void") {
		return true
	}
	p, ok := strings.CutPrefix(s, "ptr:")
	return ok && (p == "void" || validKfuncScalar(p) || validCName(p))
}

// KfuncKey encodes <name>/<ret>(<arg>,...) for recorded kfunc_protos (section 10).
func KfuncKey(name, ret string, args []string) string {
	return name + "/" + ret + "(" + strings.Join(args, ",") + ")"
}

// SysargKey encodes <syscall>/<n>/<type> for recorded syscall_args (section 10).
func SysargKey(syscall string, n int, typ string) string {
	return syscall + "/" + strconv.Itoa(n) + "/" + typ
}

// parseKfunc parses a kfunc row, associating it with its named program.
func (r *Requirements) parseKfunc(n int, f []string, line string, byName map[string]int) error {
	if _, ok := byName[f[1]]; !ok {
		return perr(n, f[0], RuleOrder, "%s line %d: kfunc for unknown program %q", Section, n, f[1])
	}
	if !validCName(f[2]) || !validKfuncType(f[3], true) {
		return perr(n, f[0], RuleValue, "%s line %d: bad kfunc row %q", Section, n, line)
	}
	for _, a := range f[4:] {
		if !validKfuncType(a, false) {
			return perr(n, f[0], RuleValue, "%s line %d: bad kfunc row %q", Section, n, line)
		}
	}
	for _, k := range r.Kfuncs {
		if k.Program == f[1] && k.Name == f[2] {
			return perr(n, f[0], RuleOrder, "%s line %d: kfunc row repeated %q", Section, n, line)
		}
	}
	r.Kfuncs = append(r.Kfuncs, Kfunc{Program: f[1], Name: f[2], Ret: f[3], Args: append([]string{}, f[4:]...)})
	return nil
}

// parseKfuncAndSyscallCompanion associates rows with the preceding attach. sysarg follows
// ksyscall arch (-> ctxfield), with strictly increasing n in 1..6. mtargetarg
// follows all N multi targets (and uprobe binary), with strictly increasing
// lexicographic (i,n), i<N, mutually exclusive with kprobearg/uprobearg.
func (r *Requirements) parseKfuncAndSyscallCompanion(n int, f []string, line string) error {
	k := len(r.Attaches) - 1
	outOfOrder := func() error {
		return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
	}
	bad := func() error { return perr(n, f[0], RuleValue, "%s line %d: bad %s row %q", Section, n, f[0], line) }
	if k < 0 || r.Attaches[k].Program != f[1] {
		return outOfOrder()
	}
	a := &r.Attaches[k]
	switch f[0] {
	case "sysarg":
		if a.AttachType != "ksyscall" || a.Arch == "" {
			return outOfOrder()
		}
		if f[3] == "strptr" && r.Version < 16 {
			return perr(n, f[0], RuleMinVersion, "%s line %d: sysarg type strptr needs version 16", Section, n)
		}
		if f[3] == "strarray" && r.Version < 16 {
			return perr(n, f[0], RuleMinVersion, "%s line %d: sysarg type strarray needs version 16", Section, n)
		}
		na, err := strconv.Atoi(f[2])
		if err != nil || na < 1 || na > SyscallMaxArgs || !(validIntSpelling(f[3]) || f[3] == "ptr" || f[3] == "strptr" || f[3] == "strarray") {
			return bad()
		}
		if l := len(a.SysArgs); l > 0 && na <= a.SysArgs[l-1].N {
			return outOfOrder()
		}
		a.SysArgs = append(a.SysArgs, KprobeArg{na, f[3]})
	case "mtargetarg":
		kp := a.AttachType == "kprobe_multi"
		if !(kp || a.AttachType == "uprobe_multi") || len(a.MTargets) != a.MultiN || len(a.KprobeArgs) > 0 || len(a.UprobeArgs) > 0 {
			return outOfOrder()
		}
		i, err1 := strconv.Atoi(f[2])
		na, err2 := strconv.Atoi(f[3])
		if err1 != nil || err2 != nil || i < 0 || na < 1 || !(validIntSpelling(f[4]) || f[4] == "ptr" || (!kp && f[4] == "strptr")) {
			return bad()
		}
		if !kp && f[4] == "ptr" && r.Version < 18 {
			return perr(n, f[0], RuleMinVersion, "%s line %d: user mtargetarg type ptr needs version 18", Section, n)
		}
		if l := len(a.MTargetArgs); l > 0 {
			p := a.MTargetArgs[l-1]
			if i < p.I || (i == p.I && na <= p.N) {
				return outOfOrder()
			}
		}
		if i >= a.MultiN {
			return perr(n, f[0], RuleValue, "%s line %d: mtargetarg index %d is not below the function count %d of the attach row %q", Section, n, i, a.MultiN, line)
		}
		a.MTargetArgs = append(a.MTargetArgs, MTargetArg{i, na, f[4]})
	}
	return nil
}

// KernelKfuncs checks target BTF kfunc FUNC_PROTO via kfunc_protos. Missing
// capabilities or unreadable BTF produce blocking kfunc_sig_unknown.
type KernelKfuncs interface {
	// CheckKfunc compares BTF FUNC name's return and argument count/types to
	// section 3 kfunc spellings. Mismatch/absence returns a message; unreadable
	// BTF wraps ErrUnknown.
	CheckKfunc(name, ret string, args []string) ([]string, error)
}

// SyscallArgCaps checks syscall_args. Missing capabilities, unreadable tracefs
// or missing event and __do_sys_<name> produce blocking sysarg_unknown. Non-root
// loaders can use recorded root caps; see docs/nonroot.md.
type SyscallArgCaps interface {
	// CheckSyscallArg compares one-based argument n to typ (i8..u64 or ptr).
	// Mismatches and missing arguments return a message.
	CheckSyscallArg(name string, n int, typ string) ([]string, error)
}

// checkKfuncs checks kfunc rows. Keep Unmet Kind as literals for spec_test's
// source/table comparison.
func checkKfuncs(req *Requirements, caps Capabilities) ([]Unmet, error) {
	var out []Unmet
	kc, ok := capsAs[KernelKfuncs](caps, QueryKfuncProtos)
	for _, k := range req.Kfuncs {
		if !ok {
			out = append(out, Unmet{Kind: "kfunc_sig_unknown", Program: k.Program, Name: k.Name, Detail: "no kfunc prototype probe"})
			continue
		}
		diffs, err := kc.CheckKfunc(k.Name, k.Ret, append([]string{}, k.Args...))
		if errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "kfunc_sig_unknown", Program: k.Program, Name: k.Name, Detail: err.Error()})
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "kfunc_sig", Program: k.Program, Name: k.Name, Detail: d})
		}
		if len(diffs) == 0 {
			u, err := checkKfuncLoad(req, k, caps)
			if err != nil {
				return nil, err
			}
			out = append(out, u...)
		}
	}
	return out, nil
}

// checkSyscallAndLSMCgroup checks typed trace_lsm_cgroup and ksyscall attaches.
func checkSyscallAndLSMCgroup(req *Requirements, a Attach, caps Capabilities, asked map[string]bool) ([]Unmet, error) {
	switch a.AttachType {
	case "trace_lsm_cgroup":
		// Preserve generic lsm_cgroup type/target checks, trace_lsm-compatible
		// bpf_lsm_<hook> farg checks and the loader declaration check.
		g := Attach{Program: a.Program, Generic: true, RetNargs: -1, ExtNargs: -1, AttachType: "lsm_cgroup", TargetKind: "lsm", TargetValue: a.Target, Target: "lsm:" + a.Target}
		out, err := checkGenericAttach(req, g, caps, asked)
		if err != nil {
			return nil, err
		}
		u, err := checkLSMArgs(a, caps)
		if err != nil {
			return nil, err
		}
		return append(out, u...), nil
	case "ksyscall":
		return checkKsyscall(a, caps)
	}
	return nil, nil
}

// KsyscallWrapper builds <prefix>sys_<name> for both checking and AttachKsyscall
// glue. An architecture missing from SyscallPrefixes returns false.
func KsyscallWrapper(arch, name string) (string, bool) {
	p, ok := SyscallPrefixes[arch]
	if !ok {
		return "", false
	}
	return p + "sys_" + name, true
}

// checkKsyscall checks arch/context like kprobe, the exact wrapper's kallsyms
// presence, syscall_args and loader ksyscall_attach. No alias is queried: the
// loader attaches the prefixed name.
func checkKsyscall(a Attach, caps Capabilities) ([]Unmet, error) {
	out, targetArch, err := checkArchAndCtx(a, caps)
	if err != nil {
		return nil, err
	}
	w, ok := KsyscallWrapper(a.Arch, a.Target)
	if !ok {
		out = append(out, Unmet{Kind: "attach_symbol_unknown", Program: a.Program, Name: a.Target, Detail: "no syscall wrapper prefix known for the arch " + strconv.Quote(a.Arch)})
	} else {
		b := a
		b.Target, b.KprobeArgs = w, nil
		if out, err = checkKprobeTarget(b, caps, out, targetArch, false); err != nil {
			return nil, err
		}
	}
	for _, s := range a.SysArgs {
		name := fmt.Sprintf("%d of syscall %s (%s)", s.N, a.Target, s.Type)
		sc, ok := capsAs[SyscallArgCaps](caps, QuerySyscallArgs)
		if !ok {
			out = append(out, Unmet{Kind: "sysarg_unknown", Program: a.Program, Name: name, Detail: "no syscall argument probe"})
			continue
		}
		diffs, err := sc.CheckSyscallArg(a.Target, s.N, s.Type)
		if errors.Is(err, ErrUnknown) {
			out = append(out, Unmet{Kind: "sysarg_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "sysarg", Program: a.Program, Name: name, Detail: d})
		}
	}
	decl := loaderOf(caps)
	switch decl.KsyscallAttach {
	case KsyscallAttachPrefix:
	case KsyscallAttachNone:
		out = append(out, Unmet{Kind: "ksyscall_loader", Program: a.Program, Name: a.Target,
			Detail: fmt.Sprintf("the loader %q does not attach a ksyscall program to the syscall wrapper %s (ksyscall_attach none — it attaches to the bare name and fails)", decl.Name, nonEmpty(w, "sys_"+a.Target))})
	default:
		out = append(out, Unmet{Kind: "ksyscall_loader_unknown", Program: a.Program, Name: a.Target,
			Detail: fmt.Sprintf("the loader %q does not declare ksyscall_attach", decl.Name)})
	}
	return out, nil
}

func nonEmpty(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// checkProgLoader checks lsm_cgroup/fsession loader declarations for generic
// and typed attach rows, returning nil for other attach kinds.
func checkProgLoader(a Attach, caps Capabilities) []Unmet {
	decl := loaderOf(caps)
	switch {
	case a.AttachType == "trace_lsm_cgroup" || (a.Generic && a.AttachType == "lsm_cgroup"):
		switch decl.LSMCgroupLoad {
		case ProgLoadBTFID:
			return nil
		case ProgLoadNone:
			return []Unmet{Unmet{Kind: "lsm_cgroup_loader", Program: a.Program, Name: a.Target,
				Detail: fmt.Sprintf("the loader %q cannot load an lsm_cgroup program (lsm_cgroup_load none — it does not set the hook's BTF id and the kernel rejects the load)", decl.Name)}}
		}
		return []Unmet{Unmet{Kind: "lsm_cgroup_loader_unknown", Program: a.Program, Name: a.Target, Detail: fmt.Sprintf("the loader %q does not declare lsm_cgroup_load", decl.Name)}}
	case a.Generic && a.AttachType == "trace_fsession":
		switch decl.FsessionLoad {
		case ProgLoadBTFID:
			return nil
		case ProgLoadNone:
			return []Unmet{Unmet{Kind: "fsession_loader", Program: a.Program, Name: a.Target,
				Detail: fmt.Sprintf("the loader %q cannot load an fsession program (fsession_load none — it does not set the function's BTF id and the kernel rejects the load)", decl.Name)}}
		}
		return []Unmet{Unmet{Kind: "fsession_loader_unknown", Program: a.Program, Name: a.Target, Detail: fmt.Sprintf("the loader %q does not declare fsession_load", decl.Name)}}
	}
	return nil
}

// mapTargetKinds maps attach types to target map types. Unlisted map: targets
// are queried through caps.
var mapTargetKinds = map[string][]string{
	"sk_skb_stream_parser":  {"sockmap", "sockhash"},
	"sk_skb_stream_verdict": {"sockmap", "sockhash"},
	"sk_skb_verdict":        {"sockmap", "sockhash"},
	"sk_msg_verdict":        {"sockmap", "sockhash"},
	"struct_ops":            {"struct_ops"},
}

// staticMapTarget answers from map rows in the same ELF. When answered is false,
// query capabilities instead.
func staticMapTarget(req *Requirements, a Attach) (answered bool, mismatch string) {
	want, ok := mapTargetKinds[a.AttachType]
	if !ok || a.TargetKind != "map" {
		return false, ""
	}
	for _, m := range req.Maps {
		if m.Symbol != a.TargetValue {
			continue
		}
		for _, w := range want {
			if m.MapType == w {
				return true, ""
			}
		}
		return true, fmt.Sprintf("%s attaches to map %s of map type %s, but this attach type needs %s (the object's map rows)", a.AttachType, m.Symbol, m.MapType, strings.Join(want, " or "))
	}
	return true, fmt.Sprintf("%s attaches to map %s, which is not a map row of the object", a.AttachType, a.TargetValue)
}

// mtargetArgsOf selects target i's arguments for the single-target checks:
// kprobe uses FUNC_PROTO n (kprobearg[_unknown]); uprobe uses symbol DWARF and ABI
// (uprobearg*). Unmet Name is <n> of <function> (<type>).
func mtargetArgsOf(a Attach, i int) []KprobeArg {
	var out []KprobeArg
	for _, m := range a.MTargetArgs {
		if m.I == i {
			out = append(out, KprobeArg{m.N, m.Type})
		}
	}
	return out
}
