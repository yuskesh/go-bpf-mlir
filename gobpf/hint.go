package gobpf

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// HintError is a load error with a likely cause (Hint) added. **The verdict and type stay those of the original error** —
// Error only appends a hint line after the original text, and errors.As / errors.Is reach the original error (*PrecheckError, *TargetError,
// *ebpf.VerifierError, EPERM and so on) through Unwrap. bpf-mlir's bindrt types and messages are not changed.
type HintError struct {
	Err  error
	Hint string
}

func (e *HintError) Error() string { return e.Err.Error() + "\n  hint: " + e.Hint }

func (e *HintError) Unwrap() error { return e.Err }

// Hints for known non-root loader failures (docs/nonroot.md — measured on all three kernels).
const (
	hintProbePermission = "the target check's capability probe was refused (permission) before the embedded program was loaded — a non-root loader needs CAP_BPF and CAP_NET_ADMIN (docs/nonroot.md)"
	hintProbePrefix     = "the target check's capability probe was refused (permission) before the embedded program was loaded — "
	hintPerfmon         = "the verifier refused pointer arithmetic for a non-root loader — a variable packet offset (ctx.Check with a non-constant offset), or on 6.x kernels a record array index whose constant default can reach the indexed access (a map value read into a variable before `if i < uint32(len(p.Arr))`), needs CAP_PERFMON in addition to CAP_BPF and CAP_NET_ADMIN (docs/nonroot.md)"
)

// withHint adds a hint to errors of a known shape (unknown errors are returned unchanged).
func withHint(err error) error {
	if err == nil {
		return nil
	}
	var pe *PrecheckError
	if errors.As(err, &pe) && (errors.Is(err, syscall.EPERM) || errors.Is(err, os.ErrPermission)) {
		h := probeHint()
		if n := nosuidHint(); n != "" {
			h += "\n  hint: " + n
		}
		return &HintError{Err: err, Hint: h}
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		var hints []string
		if at := rejectedHint(err, ve); at != "" {
			hints = append(hints, at)
		}
		if strings.Contains(strings.Join(ve.Log, "\n"), "prohibited for !root") {
			hints = append(hints, hintPerfmon)
		}
		if len(hints) > 0 {
			return &HintError{Err: err, Hint: strings.Join(hints, "\n  hint: ")}
		}
	}
	return err
}

// capFacts are the facts behind the nosuid hint: the executable's file capabilities (permitted in security.capability), the process's effective capabilities (CapEff),
// and whether the executable's mount is nosuid. **Only tests replace it** (injecting the three). An unreadable fact gives ok = false (no hint).
var capFacts = func() (exe string, fileCaps, effective uint64, nosuid, ok bool) {
	exe, err := os.Executable()
	if err != nil {
		return "", 0, 0, false, false
	}
	buf := make([]byte, 64)
	n, err := unix.Getxattr(exe, "security.capability", buf)
	if err != nil || n < 12 {
		return exe, 0, 0, false, err == nil || errors.Is(err, unix.ENODATA) // no xattr — no file capabilities (read as a fact)
	}
	// vfs_cap_data (le32 magic_etc, {le32 permitted, le32 inheritable} × 1 (v1) or 2 (v2 / v3)).
	fileCaps = uint64(binary.LittleEndian.Uint32(buf[4:8]))
	if n >= 20 {
		fileCaps |= uint64(binary.LittleEndian.Uint32(buf[12:16])) << 32
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return exe, fileCaps, 0, false, false
	}
	found := false
	for _, line := range strings.Split(string(status), "\n") {
		if v, isEff := strings.CutPrefix(line, "CapEff:"); isEff {
			if effective, err = strconv.ParseUint(strings.TrimSpace(v), 16, 64); err != nil {
				return exe, fileCaps, 0, false, false
			}
			found = true
		}
	}
	var st unix.Statfs_t
	if !found || unix.Statfs(exe, &st) != nil {
		return exe, fileCaps, effective, false, false
	}
	return exe, fileCaps, effective, st.Flags&unix.ST_NOSUID != 0, true
}

// nosuidHint returns text only when the capabilities of an executable on a nosuid mount are not in effect (only when all three facts hold):
// the executable has file capabilities, they are not in the effective capabilities, and the executable's mount is nosuid. Otherwise "" (no guessed hint).
func nosuidHint() string {
	exe, fileCaps, effective, nosuid, ok := capFacts()
	if !ok || fileCaps == 0 || effective&fileCaps == fileCaps || !nosuid {
		return ""
	}
	return fmt.Sprintf("%s carries file capabilities (setcap) that are not in effect — it is on a nosuid mount, where the kernel ignores file capabilities at exec; move the executable to a mount without nosuid (many distributions mount /tmp nosuid) or pass the capabilities at start with setpriv (docs/tutorial.md section 2)", exe)
}

// kindNeed is what a non-root loader of one program kind needs, with the source of the fact: the kernel's rule (kernel/bpf/syscall.c at 7.1.8 —
// is_net_admin_prog_type, lines 2764-2791, and is_perfmon_prog_type, lines 2795-2810, checked at BPF_PROG_LOAD, lines 2946-2949) or a measured row of docs/nonroot.md.
type kindNeed struct {
	root     bool // root only — a check in Load reads the tracefs format
	sysAdmin bool // + CAP_SYS_ADMIN (the perf uprobe attach)
	perfmon  bool
	netAdmin bool
	source   string
}

// probeKindNeeds holds every program kind the frontend emits. A kind missing from it gets the generic hint (no guessed class).
var probeKindNeeds = map[string]kindNeed{
	"tracepoint": {root: true, perfmon: true, source: "docs/nonroot.md: tracepoint programs are root only (the tpfield check reads the tracefs format — Unknown without root); syscall.c:2799 TRACEPOINT"},
	"ksyscall":   {root: true, perfmon: true, source: "docs/nonroot.md: ksyscall programs (the sysarg check reads the tracefs format — Unknown without root); syscall.c:2798 KPROBE"},

	"uprobe":    {sysAdmin: true, perfmon: true, source: "docs/nonroot.md: uprobe programs (CAP_SYS_ADMIN for the perf_uprobe attach); syscall.c:2798 KPROBE"},
	"uretprobe": {sysAdmin: true, perfmon: true, source: "docs/nonroot.md: uretprobe programs (+ CAP_SYS_ADMIN, same as uprobe); syscall.c:2798 KPROBE"},
	"usdt":      {sysAdmin: true, perfmon: true, source: "docs/nonroot.md: usdt programs (CAP_BPF + CAP_PERFMON + CAP_SYS_ADMIN — a perf uprobe); syscall.c:2798 KPROBE"},

	"kprobe":          {perfmon: true, source: "syscall.c:2798 KPROBE"},
	"kretprobe":       {perfmon: true, source: "syscall.c:2798 KPROBE"},
	"kprobe_multi":    {perfmon: true, source: "syscall.c:2798 KPROBE"},
	"kretprobe_multi": {perfmon: true, source: "syscall.c:2798 KPROBE"},
	"kprobe_session":  {perfmon: true, source: "syscall.c:2798 KPROBE"},
	"uprobe_multi":    {perfmon: true, source: "syscall.c:2798 KPROBE; docs/nonroot.md: uprobe_multi programs (no CAP_SYS_ADMIN — no perf_event_open)"},
	"uretprobe_multi": {perfmon: true, source: "syscall.c:2798 KPROBE; docs/nonroot.md: uprobe_multi programs (no CAP_SYS_ADMIN — no perf_event_open)"},
	"perf_event":      {perfmon: true, source: "syscall.c:2800 PERF_EVENT"},
	"raw_tp":          {perfmon: true, source: "syscall.c:2801 RAW_TRACEPOINT"},
	"raw_tp_writable": {perfmon: true, source: "syscall.c:2802 RAW_TRACEPOINT_WRITABLE"},
	"fentry":          {perfmon: true, source: "syscall.c:2803 TRACING"},
	"fexit":           {perfmon: true, source: "syscall.c:2803 TRACING"},
	"fsession":        {perfmon: true, source: "syscall.c:2803 TRACING"},
	"fmod_ret":        {perfmon: true, source: "syscall.c:2803 TRACING"},
	"iter":            {perfmon: true, source: "syscall.c:2803 TRACING"},
	"tp_btf":          {perfmon: true, source: "syscall.c:2803 TRACING"},
	"lsm":             {perfmon: true, source: "syscall.c:2804 LSM"},
	"lsm_s":           {perfmon: true, source: "syscall.c:2804 LSM"},
	"lsm_cgroup":      {perfmon: true, source: "syscall.c:2804 LSM"},
	"struct_ops":      {perfmon: true, source: "syscall.c:2805 STRUCT_OPS"},
	"ext":             {perfmon: true, netAdmin: true, source: "syscall.c:2783 and 2806 EXT (both lists)"},

	"sched_cls":        {netAdmin: true, source: "syscall.c:2767 SCHED_CLS"},
	"sched_act":        {netAdmin: true, source: "syscall.c:2768 SCHED_ACT"},
	"xdp":              {netAdmin: true, source: "syscall.c:2769 XDP"},
	"lwt_in":           {netAdmin: true, source: "syscall.c:2770 LWT_IN"},
	"lwt_out":          {netAdmin: true, source: "syscall.c:2771 LWT_OUT"},
	"lwt_xmit":         {netAdmin: true, source: "syscall.c:2772 LWT_XMIT"},
	"lwt_seg6local":    {netAdmin: true, source: "syscall.c:2773 LWT_SEG6LOCAL"},
	"sk_skb":           {netAdmin: true, source: "syscall.c:2774 SK_SKB"},
	"sk_msg":           {netAdmin: true, source: "syscall.c:2775 SK_MSG"},
	"flow_dissector":   {netAdmin: true, source: "syscall.c:2776 FLOW_DISSECTOR"},
	"cgroup_device":    {netAdmin: true, source: "syscall.c:2777 CGROUP_DEVICE"},
	"cgroup_sock":      {netAdmin: true, source: "syscall.c:2778 CGROUP_SOCK"},
	"cgroup_sock_addr": {netAdmin: true, source: "syscall.c:2779 CGROUP_SOCK_ADDR"},
	"cgroup_sockopt":   {netAdmin: true, source: "syscall.c:2780 CGROUP_SOCKOPT"},
	"cgroup_sysctl":    {netAdmin: true, source: "syscall.c:2781 CGROUP_SYSCTL"},
	"sock_ops":         {netAdmin: true, source: "syscall.c:2782 SOCK_OPS"},
	"netfilter":        {netAdmin: true, source: "syscall.c:2784 NETFILTER"},

	"cgroup_skb":    {source: "syscall.c:2786 CGROUP_SKB (always unpriv — CAP_BPF only)"},
	"sk_reuseport":  {source: "syscall.c:2788 SK_REUSEPORT (CAP_BPF only)"},
	"socket_filter": {source: "syscall.c:2790 default (in neither list — CAP_BPF only)"},
	"sk_lookup":     {source: "syscall.c:2790 and 2808 default (in neither list — CAP_BPF only)"},
	"syscall":       {source: "syscall.c:2790 and 2808 default (in neither list — CAP_BPF only)"},
}

// probeHint chooses the hint for the probe's EPERM by the registered object's program kinds (probeKindNeeds): root only wins, then CAP_SYS_ADMIN,
// then CAP_PERFMON, each naming the kinds that need it (and the kinds that also need CAP_NET_ADMIN). Otherwise the generic CAP_NET_ADMIN text.
func probeHint() string {
	o, err := current()
	if err != nil {
		return hintProbePermission
	}
	var root, sys, perf, net []string
	add := func(l []string, k string) []string {
		for _, s := range l {
			if s == k {
				return l
			}
		}
		return append(l, k)
	}
	for _, p := range o.Programs {
		n, ok := probeKindNeeds[p.Kind]
		switch {
		case !ok:
		case n.root:
			root = add(root, p.Kind)
		case n.sysAdmin:
			sys = add(sys, p.Kind)
		case n.perfmon:
			perf = add(perf, p.Kind)
		}
		if ok && n.netAdmin {
			net = add(net, p.Kind)
		}
	}
	also := ""
	if len(net) > 0 {
		also = "; its " + strings.Join(net, " / ") + " programs also need CAP_NET_ADMIN"
	}
	switch {
	case len(root) > 0:
		return hintProbePrefix + "the object's " + strings.Join(root, " / ") + " programs are root only: their argument check in Load reads the tracefs format, which a non-root loader cannot read, whatever its capabilities (docs/nonroot.md)"
	case len(sys) > 0:
		return hintProbePrefix + "a non-root loader of the object's " + strings.Join(sys, " / ") + " programs needs CAP_BPF, CAP_PERFMON and CAP_SYS_ADMIN (the perf uprobe attach)" + also + " (docs/nonroot.md)"
	case len(perf) > 0:
		return hintProbePrefix + "a non-root loader of the object's " + strings.Join(perf, " / ") + " programs needs CAP_BPF and CAP_PERFMON" + also + " (docs/nonroot.md)"
	}
	return hintProbePermission
}

// Format passes `%+v` and `%-Nv` to the original error: cilium's *ebpf.VerifierError prints only the last log line with `%v`, the whole log with `%+v`
// (bpf-mlir v0.6.0's line_info — including the Go line before each instruction), and the last N lines with `%-Nv`. Wrapped in a HintError the whole log stays visible
// with the same verbs (the same as an unwrapped error — the hint line comes after).
func (e *HintError) Format(f fmt.State, verb rune) {
	if verb == 'v' && (f.Flag('+') || f.Flag('-')) {
		// cilium wraps VerifierError as `program <name>: %w` (fmt's wrapping does not pass %+v on) — extract the VerifierError, pass it the format,
		// and keep the wrapping prefix (the program name).
		var ve *ebpf.VerifierError
		if errors.As(e.Err, &ve) {
			fmt.Fprint(f, strings.TrimSuffix(e.Err.Error(), ve.Error()))
			fmt.Fprintf(f, fmt.FormatString(f, verb), ve)
		} else {
			fmt.Fprintf(f, fmt.FormatString(f, verb), e.Err)
		}
		fmt.Fprintf(f, "\n  hint: %s", e.Hint)
		return
	}
	fmt.Fprint(f, e.Error())
}

// Source lines in the verifier log (bpf-mlir v0.6.0's line_info — the line string is `<file>:<line>`): 6.6 writes `; idx.go:38`, 7.1.8 / 6.12 write
// `; idx.go:38 @ idx.go:38` (pinned with actual logs from all three kernels).
var (
	verifierSourceRE = regexp.MustCompile(`^; (?:\S+ @ )?([A-Za-z0-9_.\-]+\.go:[0-9]+)$`)
	verifierInsnRE   = regexp.MustCompile(`^[0-9]+: \(`)
	programPrefixRE  = regexp.MustCompile(`^program (\S+): `)
)

// rejectedAt returns, from the verifier log, the source line (`<file>.go:<line>`) right before the refused instruction. Only when the log is complete (ending with the verifier's
// `processed N insns` line) and a source line precedes the refused instruction (the last instruction line). For a truncated log (the buffer limit) or
// the log of an ELF without line_info it returns false — it never names a wrong line.
func rejectedAt(log []string) (string, bool) {
	complete, lastInsn := false, -1
	for i, l := range log {
		l = strings.TrimSpace(l)
		if strings.HasPrefix(l, "processed ") && strings.Contains(l, " insns") {
			complete = true
		}
		if verifierInsnRE.MatchString(l) {
			lastInsn = i
		}
	}
	if !complete || lastInsn < 0 {
		return "", false
	}
	for i := lastInsn - 1; i >= 0; i-- {
		if m := verifierSourceRE.FindStringSubmatch(strings.TrimSpace(log[i])); m != nil {
			return m[1], true
		}
	}
	return "", false
}

// rejectedHint is the hint naming the Go line of a verifier refusal (`rejected <program> at <file>:<line>`). "" if it cannot be found.
func rejectedHint(err error, ve *ebpf.VerifierError) string {
	log := ve.Log
	if ve.Stats != "" { // cilium's upstream main (64d4fa2f) moves the `processed N insns` line from Log to Stats — put it back as the complete-log marker
		log = append(log[:len(log):len(log)], ve.Stats)
	}
	at, ok := rejectedAt(log)
	if !ok {
		return ""
	}
	prog := "the program"
	if m := programPrefixRE.FindStringSubmatch(err.Error()); m != nil {
		prog = "program " + m[1]
	}
	return fmt.Sprintf("the verifier rejected %s at %s (the Go line of the rejected instruction — format the error with %%+v for the whole verifier log)", prog, at)
}
