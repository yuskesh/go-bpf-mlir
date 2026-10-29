package frontend

import (
	"go/ast"
	"go/token"
	"go/types"
	"regexp"
	"strconv"
	"strings"
)

// The program kind table (extends "the context type marks the program" beyond XDP).
// Per context type: the bpf-mlir kind, attach (direction), verdict type, verdict value spellings and user-space attach kind.
type ctxKind struct {
	Type       string           // the bpf context type name
	Kind       string           // the ebpf.program kind (the schema kind)
	Attach     string           // the ebpf.program attach (the sched_cls direction — "" for xdp)
	Action     string           // the verdict type name (bpf.XDPAction / bpf.TCAction)
	Verdicts   map[int64]string // verdict value → ebpf.verdict spelling (bpf-mlir's per-kind table — UAPI values)
	AttachKind string           // the user-space attach (BpfEntry.AttachKind)
	// IntRet is the value range for kinds that return an i32 constant with ebpf.return instead of a verdict spelling (lsm's −4095..0). nil for Verdicts kinds.
	IntRet *[2]int64
	// IntRetExpr reports whether an IntRet kind accepts a computed i32 expression as the result (fmod_ret, syscall and ext; lsm stays constants only — the accepted
	// shapes of existing kinds are not widened).
	IntRetExpr bool
	// Multi marks a multi probe kind with the same context type as a single kind — ctxKindOf returns the single row, and the directive
	// `//gobpf:<multi kind>` selects the multi row (multiKindFor).
	Multi bool
}

var ctxKinds = []*ctxKind{
	{Type: "XDPContext", Kind: "xdp", Action: "XDPAction", Verdicts: map[int64]string{0: "aborted", 1: "drop", 2: "pass", 3: "tx"}, AttachKind: "xdp-ifindex"},
	{Type: "TCIngressContext", Kind: "sched_cls", Attach: "ingress", Action: "TCAction", Verdicts: map[int64]string{0: "pass", 2: "drop"}, AttachKind: "tcx"},
	{Type: "TCEgressContext", Kind: "sched_cls", Attach: "egress", Action: "TCAction", Verdicts: map[int64]string{0: "pass", 2: "drop"}, AttachKind: "tcx"},
	// fentry: no result (Action "") — the verdict is only done. The attach target (a kernel function) comes from the directive `//gobpf:fentry <fn>` (per program).
	{Type: "FentryContext", Kind: "fentry", AttachKind: "fentry"},
	// fexit: no result; the attach target and argument count come from `//gobpf:fexit <fn> nargs=<N>`, the return type is the context type argument R.
	{Type: "FexitContext", Kind: "fexit", AttachKind: "fexit"},
	// kprobe: no result; the attach target is `//gobpf:kprobe <fn>`, arch x86_64, arguments via bpf.KprobeArg[T](ctx, n) (the schema params).
	{Type: "KprobeContext", Kind: "kprobe", AttachKind: "kprobe"},
	// uprobe: no result; the attach target is `//gobpf:uprobe <binary path> <symbol>` (the path is only checked at generate time), arguments via UprobeArg / UprobeStr.
	{Type: "UprobeContext", Kind: "uprobe", AttachKind: "uprobe"},
	// tp_btf: no result; the attach target (tracepoint) is `//gobpf:tp_btf <tracepoint>`, arguments via bpf.TPArg[T](ctx, i) (the schema program args — a positional array).
	{Type: "TPBTFContext", Kind: "tp_btf", AttachKind: "tp_btf"},
	// bpf-mlir v1.10.0: no result (done). tracepoint uses `//gobpf:tracepoint <category>/<event>` and the event struct E (TracepointContext[E] —
	// tagged fields become the schema fields), raw_tp uses `//gobpf:raw_tp <tracepoint>` (RawTPArg), kretprobe / uretprobe use the kprobe / uprobe directive shape and
	// the return type R (Ret — ebpf.probe.retval).
	{Type: "TracepointContext", Kind: "tracepoint", AttachKind: "tracepoint"},
	{Type: "RawTPContext", Kind: "raw_tp", AttachKind: "raw_tp"},
	// bpf-mlir's raw_tp_writable: `//gobpf:raw_tp_writable <tracepoint>`, Buffer / SetBuffer on the writable buffer, no result.
	{Type: "RawTPWritableContext", Kind: "raw_tp_writable", AttachKind: "raw_tp"},
	{Type: "KretprobeContext", Kind: "kretprobe", AttachKind: "kretprobe"},
	{Type: "UretprobeContext", Kind: "uretprobe", AttachKind: "uretprobe"},
	// bpf-mlir v1.10.0: socket and cgroup. The cgroup-family verdict is deny 0 / allow 1, socket_filter is drop 0 / keep −1 (the u32 maximum).
	// The cgroup_skb direction is in the type (as with tcx); the cgroup_sock / cgroup_sock_addr hook is a directive. Fields are methods (sockcg.go's table).
	{Type: "SocketFilterContext", Kind: "socket_filter", Action: "SocketFilterAction", Verdicts: map[int64]string{0: "drop", -1: "keep"}, AttachKind: "socket"},
	{Type: "CgroupSKBIngressContext", Kind: "cgroup_skb", Attach: "ingress", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	{Type: "CgroupSKBEgressContext", Kind: "cgroup_skb", Attach: "egress", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	{Type: "CgroupSockContext", Kind: "cgroup_sock", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	{Type: "SockAddrContext", Kind: "cgroup_sock_addr", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	{Type: "SockOpsContext", Kind: "sock_ops", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	// bpf-mlir's cgroup_device: no directive, fields are methods (read-only), the verdict is the same as the cgroup family.
	{Type: "CgroupDeviceContext", Kind: "cgroup_device", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	// bpf-mlir's cgroup_sysctl: no directive, write / file_pos methods and SetNewValue (a string constant).
	// bpf-mlir's cgroup_sockopt: the direction is in the type (as with cgroup_skb), level / optname / optlen methods and the optval window (Check).
	{Type: "CgroupSetsockoptContext", Kind: "cgroup_sockopt", Attach: "setsockopt", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	{Type: "CgroupGetsockoptContext", Kind: "cgroup_sockopt", Attach: "getsockopt", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	{Type: "CgroupSysctlContext", Kind: "cgroup_sysctl", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	// bpf-mlir v1.11.0 feature paths F42, F64: lsm and lsm.s — the hook is `//gobpf:lsm <hook>` / `//gobpf:lsm_s <hook>`, the result is an LSMRet
	// constant −4095..0 (an ebpf.return i32 — not a verdict spelling), arguments via LSMArg / LSMArgInt (the schema args — the requirements' farg).
	{Type: "LSMContext", Kind: "lsm", Action: "LSMRet", AttachKind: "lsm", IntRet: &lsmRetRange},
	{Type: "LSMSleepableContext", Kind: "lsm_s", Action: "LSMRet", AttachKind: "lsm", IntRet: &lsmRetRange},
	// bpf-mlir's lsm_cgroup: the hook is `//gobpf:lsm_cgroup <hook>`, no arguments, the verdict is deny 0 / allow 1 as in the cgroup family.
	{Type: "LSMCgroupContext", Kind: "lsm_cgroup", Action: "CgroupAction", Verdicts: map[int64]string{0: "deny", 1: "allow"}, AttachKind: "cgroup"},
	// bpf-mlir v1.11.0 feature path F45: perf_event — no result (done), no directive (the attach target is the user's perf event fd), arch x86_64,
	// the ctx has only SamplePeriod (ebpf.ctx.field "sample_period" -> i64).
	{Type: "PerfEventContext", Kind: "perf_event", AttachKind: "perf_event"},
	// bpf-mlir's fsession: no result (done), directive `//gobpf:fsession <kernel function>`, the ctx has only the session ops.
	{Type: "FsessionContext", Kind: "fsession", AttachKind: "fentry"},
	// bpf-mlir's fmod_ret: directive `//gobpf:fmod_ret <kernel function> nargs=<N>` (retsig), arguments via FmodRetArgInt
	// (integers only — farg), the result is a computed i32 (ebpf.return — 0 runs the original function, nonzero skips it; the kernel does not check the range).
	{Type: "FmodRetContext", Kind: "fmod_ret", Action: "FmodRet", AttachKind: "fentry", IntRet: &fmodRetRange, IntRetExpr: true},
	// bpf-mlir's kprobe_session: directive `//gobpf:kprobe_session <kernel function>`, session ops (as in fsession),
	// the result is a constant 0 / 1 (ebpf.return — 1 at entry skips the return run), no arguments.
	// bpf-mlir's syscall: no directive, no attach (test run), ctx reads via SyscallLoad (ebpf.ctx.load), the result is a computed
	// i32 (an explicit IntRetExpr opt-in — the test run's retval).
	{Type: "SyscallContext", Kind: "syscall", Action: "SyscallRet", AttachKind: "test-run", IntRet: &fmodRetRange, IntRetExpr: true},
	// bpf-mlir's ext: directive `//gobpf:ext <program> <global function>`, arguments via ExtArg (ebpf.ext.arg),
	// the result is the replaced function's integer result type (ebpf.return — Action is only a marker, not a bpf type: collectPrograms and checkExtPrograms check the result type).
	{Type: "ExtContext", Kind: "ext", Action: "ExtRet", AttachKind: "ext", IntRet: &fmodRetRange, IntRetExpr: true},
	// bpf-mlir's struct_ops: directive `//gobpf:struct_ops <map> <member>`, the result follows the member table (void is done,
	// uint32 is an ebpf.return of a computed value — collectPrograms splits rows per member, structOpsKind).
	{Type: "StructOpsContext", Kind: "struct_ops", AttachKind: "struct_ops"},
	{Type: "KprobeSessionContext", Kind: "kprobe_session", Action: "KprobeSessionRet", AttachKind: "kprobe-multi", IntRet: &ksessRetRange},
	// bpf-mlir's iter: no result (done), directive `//gobpf:iter bpf_map_elem <map>`, the ctx has only SeqNum / Seq.
	{Type: "IterContext", Kind: "iter", AttachKind: "iter"},
	// bpf-mlir v1.11.0 feature paths F65 / F67: ksyscall — no result (done), attach via `//gobpf:ksyscall <syscall>` (the syscall name only —
	// gobpf attaches to `__x64_sys_<name>`), arch x86_64, arguments via KsyscallArg (the schema params — the requirements' sysarg).
	{Type: "KsyscallContext", Kind: "ksyscall", AttachKind: "ksyscall"},
	// bpf-mlir v1.11.0 feature path F54: kprobe_multi / kretprobe_multi — the context is the same type as the single kind; the directive `//gobpf:kprobe_multi f1 f2 …`
	// selects it (Multi — ctxKindOf does not return it). attach is a list (ebpf.program's `attach ["f1", "f2"]`, an array in the schema's attach_target), arch x86_64.
	{Type: "KprobeContext", Kind: "kprobe_multi", AttachKind: "kprobe_multi", Multi: true},
	{Type: "KretprobeContext", Kind: "kretprobe_multi", AttachKind: "kretprobe_multi", Multi: true},
	// uprobe_multi / uretprobe_multi — the same type as single uprobe / uretprobe, directive `//gobpf:uprobe_multi <path> s1 s2 …`.
	{Type: "UprobeContext", Kind: "uprobe_multi", AttachKind: "uprobe_multi", Multi: true},
	{Type: "UretprobeContext", Kind: "uretprobe_multi", AttachKind: "uretprobe_multi", Multi: true},
	// bpf-mlir v1.11.0's usdt: no result (done), attach via `//gobpf:usdt <path> <provider>:<name>`, arch x86_64,
	// arguments via USDTArg (value and status — the schema params), the index via ProbeTargetIndex (the point number).
	{Type: "USDTContext", Kind: "usdt", AttachKind: "usdt"},
	// bpf-mlir v1.11.0: sk_skb (stream_verdict) — attach via `//gobpf:sk_skb <map>` (a sockmap / sockhash
	// variable — the ebpf.program attach symbol), verdict sk_action (drop 0, pass 1), terminators Redirect / RedirectIf (sk.redirect).
	{Type: "SKSKBContext", Kind: "sk_skb", Action: "SKAction", Verdicts: map[int64]string{0: "drop", 1: "pass"}, AttachKind: "sockmap"},
	// bpf-mlir v1.11.0: sk_msg — the same directive and verdict as sk_skb, terminators MsgRedirect / MsgRedirectIf (msg.redirect).
	// bpf-mlir's sk_lookup: no directive, fields are methods (read-only — remote_port is a 2-byte be16), the verdict is sk_action.
	// bpf-mlir's lwt_in / out / xmit: no directive, len and packet window reads, verdict bpf_ret_code ok / drop, attached as a route encap.
	{Type: "LWTInContext", Kind: "lwt_in", Action: "LWTAction", Verdicts: map[int64]string{0: "ok", 2: "drop"}, AttachKind: "lwt-route"},
	{Type: "LWTOutContext", Kind: "lwt_out", Action: "LWTAction", Verdicts: map[int64]string{0: "ok", 2: "drop"}, AttachKind: "lwt-route"},
	{Type: "LWTXmitContext", Kind: "lwt_xmit", Action: "LWTAction", Verdicts: map[int64]string{0: "ok", 2: "drop"}, AttachKind: "lwt-route"},
	// bpf-mlir's lwt_seg6local: no directive, 5 ctx fields (mark / priority also writable), verdict ok / drop (redirect is not emitted),
	// attached as a seg6local route's End.BPF.
	{Type: "Seg6LocalContext", Kind: "lwt_seg6local", Action: "Seg6Action", Verdicts: map[int64]string{0: "ok", 2: "drop"}, AttachKind: "seg6local-route"},
	// bpf-mlir's netfilter: no directive, kfield reads of the state / skb kptrs, verdict nf drop / accept.
	{Type: "NetfilterContext", Kind: "netfilter", Action: "NFAction", Verdicts: map[int64]string{0: "drop", 1: "accept"}, AttachKind: "netfilter"},
	// bpf-mlir's flow_dissector: no directive, the packet window and flow_keys methods, verdict bpf_ret_code ok / drop / continue.
	{Type: "FlowDissectorContext", Kind: "flow_dissector", Action: "FlowAction", Verdicts: map[int64]string{0: "ok", 2: "drop", 129: "flow_dissector_continue"}, AttachKind: "netns"},
	// bpf-mlir's sk_reuseport: no directive (attach "" = select), reads of 5 fields and ReuseportSockArray.Select, the verdict is sk_action.
	{Type: "SkReuseportContext", Kind: "sk_reuseport", Action: "SKAction", Verdicts: map[int64]string{0: "drop", 1: "pass"}, AttachKind: "socket"},
	{Type: "SkLookupContext", Kind: "sk_lookup", Action: "SKAction", Verdicts: map[int64]string{0: "drop", 1: "pass"}, AttachKind: "netns"},
	{Type: "SKMsgContext", Kind: "sk_msg", Action: "SKAction", Verdicts: map[int64]string{0: "drop", 1: "pass"}, AttachKind: "sockmap"},
	// bpf-mlir v1.11.0: sched_act — no attach (test run only — a real attach via netlink act_bpf is out of scope), verdict tc_act
	// ok 0, shot 2, pipe 3; the ctx has len reads, mark writes and the packet window.
	{Type: "TCActContext", Kind: "sched_act", Action: "TCActAction", Verdicts: map[int64]string{0: "ok", 2: "shot", 3: "pipe"}, AttachKind: "test-run"},
}

// isSockmapProgKind reports whether kind attaches to a sockmap / sockhash (the directive is the map name).
func isSockmapProgKind(kind string) bool { return kind == "sk_skb" || kind == "sk_msg" }

// hasTargetIndex reports whether kind has ProbeTargetIndex (the four multi kinds and usdt — the OPS of bpf-mlir's probe.target_index).
func hasTargetIndex(kind string) bool { return isMultiKind(kind) || kind == "usdt" }

// usdtTarget matches a USDT point `<provider>:<name>` (both C identifiers).
var usdtTarget = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*:[A-Za-z_][A-Za-z0-9_]*$`)

// multiKinds maps a single kind to its multi kind (the directive name).
var multiKinds = map[string]string{"kprobe": "kprobe_multi", "kretprobe": "kretprobe_multi", "uprobe": "uprobe_multi", "uretprobe": "uretprobe_multi"}

// isMultiKind reports whether kind is a multi probe kind.
func isMultiKind(kind string) bool {
	return kind == "kprobe_multi" || kind == "kretprobe_multi" || kind == "uprobe_multi" || kind == "uretprobe_multi"
}

// isUprobeKind reports whether kind attaches to a user binary symbol (uprobe, uretprobe and their two multi kinds — binary check and path directive).
func isUprobeKind(kind string) bool {
	return kind == "uprobe" || kind == "uretprobe" || kind == "uprobe_multi" || kind == "uretprobe_multi"
}

// isRetprobeKind reports whether kind is a probe kind that reads the return value (ctx.Ret — ebpf.probe.retval).
func isRetprobeKind(kind string) bool {
	return kind == "kretprobe" || kind == "uretprobe" || kind == "kretprobe_multi" || kind == "uretprobe_multi"
}

// multiKindFor returns the multi row if fd's doc directive is the multi kind of the single kind ck (`//gobpf:kprobe_multi …`), otherwise ck.
func multiKindFor(fd *ast.FuncDecl, ck *ctxKind) *ctxKind {
	mk, ok := multiKinds[ck.Kind]
	if !ok || fd.Doc == nil {
		return ck
	}
	for _, c := range fd.Doc.List {
		if m := directiveRE.FindStringSubmatch(c.Text); m != nil && m[1] == mk {
			for _, k := range ctxKinds {
				if k.Kind == mk {
					return k
				}
			}
		}
	}
	return ck
}

// lsmRetRange is the return value range of an int lsm hook (the kernel verifier and bpf-mlir's ebpf.return check — −MAX_ERRNO..0).
var lsmRetRange = [2]int64{-4095, 0}

// fmodRetRange is the constant return value range of fmod_ret (all of i32: the kernel's check_return_code does not check the range for BPF_MODIFY_RETURN).
var fmodRetRange = [2]int64{-1 << 31, 1<<31 - 1}

// ksessRetRange is the return value range of kprobe_session (bpf-mlir's verdict `done|int:0..1`).
var ksessRetRange = [2]int64{0, 1}

// isTracingProgramKind reports whether kind names its attach target in a directive (the tracing kinds, and the cgroup_sock / cgroup_sock_addr hooks too).
func isTracingProgramKind(kind string) bool {
	switch kind {
	case "fentry", "fexit", "kprobe", "uprobe", "tp_btf", "tracepoint", "raw_tp", "kretprobe", "uretprobe", "lsm", "lsm_s", "lsm_cgroup", "ksyscall", "usdt", "fsession", "iter", "fmod_ret", "raw_tp_writable", "kprobe_session", "ext", "struct_ops":
		return true
	}
	if isSockmapProgKind(kind) {
		return true
	}
	if isMultiKind(kind) {
		return true
	}
	_, hook := hookKinds[kind]
	return hook
}

// directiveUsage returns how to write a tracing kind's directive (for diagnostics).
func directiveUsage(kind string) string {
	switch kind {
	case "uprobe", "uretprobe":
		return "//gobpf:" + kind + " <binary path> <symbol>"
	case "fexit", "fmod_ret":
		return "//gobpf:" + kind + " <kernel function> nargs=<N>"
	case "tp_btf", "raw_tp", "raw_tp_writable":
		return "//gobpf:" + kind + " <tracepoint>"
	case "tracepoint":
		return "//gobpf:tracepoint <category>/<event>"
	case "lsm", "lsm_s", "lsm_cgroup":
		return "//gobpf:" + kind + " <LSM hook>"
	case "ksyscall":
		return "//gobpf:ksyscall <syscall>"
	case "kprobe_multi", "kretprobe_multi":
		return "//gobpf:" + kind + " <kernel function> <kernel function> …"
	case "uprobe_multi", "uretprobe_multi":
		return "//gobpf:" + kind + " <binary path> <symbol> <symbol> …"
	case "usdt":
		return "//gobpf:usdt <binary path> <provider>:<name>"
	case "sk_skb", "sk_msg":
		return "//gobpf:" + kind + " <sockmap or sockhash variable>"
	case "iter":
		return "//gobpf:iter bpf_map_elem <map variable>"
	case "ext":
		return "//gobpf:ext <program> <global function>"
	case "struct_ops":
		return "//gobpf:struct_ops <struct_ops map> <member>"
	}
	if hooks, ok := hookKinds[kind]; ok {
		return "//gobpf:" + kind + " <" + strings.Join(hooks, "|") + ">"
	}
	return "//gobpf:" + kind + " <kernel function>"
}

// tracefsEventName matches a tracepoint's `<category>/<event>` (the two levels of tracefs's events directory — each a C identifier).
var tracefsEventName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*/[A-Za-z_][A-Za-z0-9_]*$`)

// ctxKindOf returns the kind if t is *bpf.<context>.
func ctxKindOf(t types.Type) *ctxKind {
	p, ok := t.(*types.Pointer)
	if !ok {
		return nil
	}
	for _, k := range ctxKinds {
		if !k.Multi && isBPFNamed(p.Elem(), k.Type) {
			return k
		}
	}
	return nil
}

// isContextType reports whether t is a context type (a pointer to it or the type itself).
func isContextType(t types.Type) bool {
	if ctxKindOf(t) != nil {
		return true
	}
	for _, k := range ctxKinds {
		if isBPFNamed(t, k.Type) {
			return true
		}
	}
	return false
}

// The directive `//gobpf:<kind> <arg>` (the attach target of fentry and others).
var (
	directiveRE    = regexp.MustCompile(`^//gobpf:(\S*)\s*(.*)$`)
	kernelFuncName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`) // a kernel function name (including suffixes like `.isra.0`)
)

// tracingTarget returns the attach function name, and fexit's argument count, from the doc directive just before the tracing program fd (kind "fentry" / "fexit"):
// `//gobpf:fentry <fn>`, `//gobpf:fexit <fn> nargs=<0..12>`. Exactly one directive (none, two, a malformed name, another kind, nargs on fentry, or a missing or
// out-of-range nargs on fexit is GB008 — a review point). The nargs limit 12 is the kernel's MAX_BPF_FUNC_ARGS (bpf-mlir's schema is also 0..12).
func (a *analyzer) tracingTarget(fd *ast.FuncDecl, kind string) (string, int, bool) {
	var found []string
	var at token.Pos = fd.Name.Pos()
	if fd.Doc != nil {
		for _, c := range fd.Doc.List {
			m := directiveRE.FindStringSubmatch(c.Text)
			if m == nil {
				continue
			}
			at = c.Pos()
			if m[1] != kind {
				a.report(Rejected, GB008ProgramShape, c.Pos(), []string{fd.Name.Name}, "directive //gobpf:%s is not supported (the %s program %s takes %s)", m[1], kind, fd.Name.Name, directiveUsage(kind))
				return "", 0, false
			}
			found = append(found, strings.TrimSpace(m[2]))
		}
	}
	switch {
	case len(found) == 0:
		switch kind {
		case "tracepoint", "raw_tp", "kretprobe", "uretprobe", "cgroup_sock", "cgroup_sock_addr", "lsm", "lsm_s", "lsm_cgroup", "ksyscall", "usdt", "sk_skb", "sk_msg", "iter", "raw_tp_writable", "ext", "struct_ops":
			a.report(Rejected, GB008ProgramShape, fd.Name.Pos(), []string{fd.Name.Name}, "the %s program %s needs its attach point — write `%s` right above `func %s`", kind, fd.Name.Name, directiveUsage(kind), fd.Name.Name)
		default:
			a.report(Rejected, GB008ProgramShape, fd.Name.Pos(), []string{fd.Name.Name}, "the %s program %s needs the kernel function to attach to — write `//gobpf:%s <function>%s` right above `func %s`", kind, fd.Name.Name, kind, map[string]string{"fexit": " nargs=<N>", "fmod_ret": " nargs=<N>"}[kind], fd.Name.Name)
		}
		return "", 0, false
	case len(found) > 1:
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "the %s program %s has %d //gobpf:%s directives — write exactly one", kind, fd.Name.Name, len(found), kind)
		return "", 0, false
	}
	fields := strings.Fields(found[0])
	if isUprobeKind(kind) { // uprobe_multi / uretprobe_multi too — a path and a list of symbols
		return a.uprobeDirective(fd, at, kind, fields)
	}
	if kind == "ext" { // the target program and the global function
		return a.extDirective(fd, at, fields)
	}
	if kind == "struct_ops" { // the struct_ops map and member
		return a.structOpsDirective(fd, at, fields)
	}
	if kind == "usdt" { // a path and a USDT point
		return a.usdtDirective(fd, at, fields)
	}
	if isSockmapProgKind(kind) { // the sockmap / sockhash variable to attach to
		return a.sockmapDirective(fd, at, kind, fields)
	}
	if hooks, ok := hookKinds[kind]; ok {
		// One word, the hook name (the attach table of bpf-mlir's ProgramAttaches.def — unix hooks are out of scope).
		for _, h := range hooks {
			if len(fields) == 1 && fields[0] == h {
				return h, 0, true
			}
		}
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s takes one hook name (%s), got %q", kind, strings.Join(hooks, ", "), found[0])
		return "", 0, false
	}
	if kind == "tracepoint" {
		// One word `<category>/<event>` (a tracefs event — the name's existence and fields are checked at load time: trace_tp / tpfield).
		if len(fields) != 1 || !tracefsEventName.MatchString(fields[0]) {
			a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:tracepoint takes one tracefs event as `<category>/<event>` (e.g. syscalls/sys_enter_getppid), got %q", found[0])
			return "", 0, false
		}
		return fields[0], 0, true
	}
	if isMultiKind(kind) {
		// A list of kernel function names (one or more, no duplicates, no globs, no `__x64_` aliases — existence is checked at load time by mtarget).
		if !a.multiList(fd, at, kind, fields, "kernel function") {
			return "", 0, false
		}
		return strings.Join(fields, " "), 0, true
	}
	if kind == "ksyscall" && (len(fields) != 1 || !cIdent.MatchString(fields[0]) || strings.HasPrefix(fields[0], "__") || strings.HasPrefix(fields[0], "sys_")) {
		// One word, the syscall name (gobpf adds the `__x64_sys_` wrapper prefix — existence and argument types are checked at load time: ksyscall / sysarg).
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:ksyscall takes one syscall name without the wrapper prefix (e.g. getppid, prctl — gobpf attaches to __x64_sys_<name>), got %q", found[0])
		return "", 0, false
	}
	if (isLSMKind(kind) || kind == "lsm_cgroup") && (len(fields) != 1 || !cIdent.MatchString(fields[0]) || strings.HasPrefix(fields[0], "bpf_lsm_")) {
		// One word, the hook name (<hook> of the kernel's bpf_lsm_<hook> — existence and argument types are checked at load time: trace_lsm / farg).
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s takes one LSM hook name without the bpf_lsm_ prefix (e.g. socket_create, file_open), got %q", kind, found[0])
		return "", 0, false
	}
	if kind == "iter" { // `//gobpf:iter bpf_map_elem <map>`
		return a.iterDirective(fd, at, fields)
	}
	if len(fields) == 0 || !kernelFuncName.MatchString(fields[0]) {
		name := ""
		if len(fields) > 0 {
			name = fields[0]
		}
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s %q is not a kernel function name (letters, digits, _ and .)", kind, name)
		return "", 0, false
	}
	if kind == "kprobe" && strings.HasPrefix(fields[0], "__x64_") {
		// gobpf never rewrites to an alias — the declaration is the kernel function itself (the rule that stops cilium's silent `__x64_` rewrite before load).
		// kretprobe reads only the return value (rax), so it may name the wrapper — load's attach_alias stops a rewrite to a name not written.
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:kprobe %s: write the kernel function itself, not its %q syscall wrapper alias (the wrapper takes a pt_regs, not the arguments — KprobeArg would read the wrong registers)", fields[0], "__x64_")
		return "", 0, false
	}
	if kind != "fexit" && kind != "fmod_ret" { // fmod_ret too — the retsig argument count
		if len(fields) > 1 {
			a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s takes only the kernel function name (%q is extra — nargs is for //gobpf:fexit, whose program reads the return value)", kind, strings.Join(fields[1:], " "))
			return "", 0, false
		}
		return fields[0], 0, true
	}
	// fexit: exactly one nargs=<0..12> (a literal).
	n, ok := -1, len(fields) == 2 && strings.HasPrefix(fields[1], "nargs=")
	if ok {
		v, err := strconv.Atoi(strings.TrimPrefix(fields[1], "nargs="))
		ok = err == nil && v >= 0 && v <= 12
		n = v
	}
	if !ok {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s needs the number of arguments of the kernel function as `nargs=<0..12>` (a literal — the return value sits after them; 12 is the kernel's MAX_BPF_FUNC_ARGS): got %q", kind, found[0])
		return "", 0, false
	}
	return fields[0], n, true
}

// multiList checks the name list of a multi probe directive (one or more, no duplicates, no globs, the name shape, and no `__x64_` aliases for kernel functions;
// the same for user symbols). noun is the diagnostic noun ("kernel function" / "symbol"). On error it reports and returns false.
func (a *analyzer) multiList(fd *ast.FuncDecl, at token.Pos, kind string, names []string, noun string) bool {
	seen := map[string]bool{}
	for _, f := range names {
		switch {
		case strings.ContainsAny(f, "*?["):
			a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s %q: a glob is not supported — list the %ss by name", kind, f, noun)
			return false
		case !kernelFuncName.MatchString(f):
			a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s %q is not a %s name (letters, digits, _ and .)", kind, f, noun)
			return false
		case noun == "kernel function" && strings.HasPrefix(f, "__x64_"):
			a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s %s: write the kernel function itself, not its %q syscall wrapper alias (the wrapper takes a pt_regs, not the arguments)", kind, f, "__x64_")
			return false
		case seen[f]:
			a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s lists %s twice — each %s once (its position is its index)", kind, f, noun)
			return false
		}
		seen[f] = true
	}
	if len(names) == 0 {
		a.report(Rejected, GB008ProgramShape, at, []string{fd.Name.Name}, "//gobpf:%s needs at least one %s (`%s`)", kind, noun, directiveUsage(kind))
		return false
	}
	return true
}

// checkStrayDirectives stops `//gobpf:` directives outside a fentry program's doc (on non-func declarations, inside functions, above a func with a different
// context type — a review point). directiveOf holds the comment groups of fentry program docs.
func (a *analyzer) checkStrayDirectives() {
	for _, f := range a.files() {
		for _, cg := range f.Comments {
			if a.directiveOf[cg] {
				continue
			}
			for _, c := range cg.List {
				if m := directiveRE.FindStringSubmatch(c.Text); m != nil {
					a.report(Rejected, GB008ProgramShape, c.Pos(), nil, "//gobpf:%s is only allowed right above a fentry program (func f(ctx *bpf.FentryContext)), a fexit program or a kprobe program (func f(ctx *bpf.KprobeContext)) — or another tracing program (uprobe, tp_btf, tracepoint, raw_tp, kretprobe, uretprobe), a cgroup_sock / cgroup_sock_addr program, a lsm / lsm_s / lsm_cgroup program, a ksyscall program, a fsession program (func f(ctx *bpf.FsessionContext) with no result) or an iter program (func f(ctx *bpf.IterContext) with no result)", m[1])
				}
			}
		}
	}
}
