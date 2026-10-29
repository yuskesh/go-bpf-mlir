//go:build linux

package kload

// Probe expected_attach_type and context access using target-BTF names and
// flattened offsets. Missing BTF enum/field names are definitive false. A
// candidate load acceptance is true; rejection needs an accepted control and
// the appropriate verifier/errno evidence, otherwise Unknown. Context controls
// omit the access. Attach-type controls use expected_attach_type zero. Types
// requiring attach BTF remain Unknown except known tracing/LSM load targets.
// Sockmap and multi-probe types also need a link probe after successful load:
// create and immediately close links on an empty sockmap, a kernel test
// function or a never-called self-process uprobe point. Missing mechanisms
// yield false; unrelated failures yield Unknown. Attach-target metadata probes
// distinguish built-in-only names from possibly module-owned names below.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

var (
	attachCtxMu    sync.Mutex
	attachCtxCache = map[string]attachCtxResult{}
)

type attachCtxResult struct {
	ok  bool
	err error
}

func cachedProbe(key string, f func() (bool, error)) (bool, error) {
	attachCtxMu.Lock()
	defer attachCtxMu.Unlock()
	if r, ok := attachCtxCache[key]; ok {
		return r.ok, r.err
	}
	ok, err := f()
	attachCtxCache[key] = attachCtxResult{ok, err}
	return ok, err
}

func unknownf(format string, a ...any) error {
	return fmt.Errorf(format+": %w", append(a, requirements.ErrUnknown)...)
}

// Program types requiring attach BTF cannot be probed by expected_attach_type alone.
var btfAttachTypes = map[ebpf.ProgramType]bool{ebpf.Tracing: true, ebpf.LSM: true, ebpf.Extension: true, ebpf.StructOps: true}

// linkOnlyAttachType identifies link-create types that are not load-time
// expected_attach_type values. Do not probe them as the latter: that would
// turn a future load rejection into an incorrect blocking attach_type mismatch.
// See docs/requirements_format.md section 4.
func linkOnlyAttachType(pt ebpf.ProgramType, attachType string) bool {
	return pt == ebpf.PerfEvent && attachType == "perf_event"
}

// AttachTypeValue resolves uppercase BPF_<name> in target bpf_attach_type BTF;
// found=false means no such enum value.
func AttachTypeValue(name string) (value uint64, found bool, err error) {
	spec, err := vmlinux()
	if err != nil {
		return 0, false, err
	}
	var e *btf.Enum
	if err := spec.TypeByName("bpf_attach_type", &e); err != nil {
		return 0, false, err
	}
	want := "BPF_" + strings.ToUpper(name)
	for _, v := range e.Values {
		if v.Name == want {
			return v.Value, true, nil
		}
	}
	return 0, false, nil
}

// loadOutcome retains acceptance, verifier rejection, EINVAL and diagnostic text.
type loadOutcome struct {
	accepted, verifierReject, einval bool
	text                             string
}

func loadProbe(pt ebpf.ProgramType, at ebpf.AttachType, ins asm.Instructions) loadOutcome {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ebpf_probe", Type: pt, AttachType: at, Instructions: ins, License: "GPL"})
	if err == nil {
		p.Close()
		return loadOutcome{accepted: true, text: "accept"}
	}
	return outcomeOf(err)
}

func outcomeOf(err error) loadOutcome {
	var ve *ebpf.VerifierError
	return loadOutcome{verifierReject: errors.As(err, &ve), einval: errors.Is(err, unix.EINVAL), text: strings.SplitN(err.Error(), "\n", 2)[0]}
}

// sockmapLinkAttach covers sk_skb/sk_msg links to sockmap/sockhash. struct_ops
// also attaches to a map but uses a different mechanism and is excluded.
func sockmapLinkAttach(pt ebpf.ProgramType) bool { return pt == ebpf.SkSKB || pt == ebpf.SkMsg }

// sockmapLinkProbe first loads the minimal program, using paired-load verdicts
// on failure. On acceptance, create an empty map and a raw BPF_LINK_CREATE link
// without fallback, then immediately close it (no sockets are affected).
// Success means true; a well-formed EINVAL or ErrNotSupported means false.
// All other failures, including map creation EPERM, are Unknown. Never PROG_ATTACH.
func sockmapLinkProbe(progType string, pt ebpf.ProgramType, attachType string, at ebpf.AttachType) (bool, error) {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ebpf_probe", Type: pt, AttachType: at, Instructions: retZero(), License: "GPL"})
	if err != nil {
		x := outcomeOf(err)
		ctl := loadProbe(pt, 0, retZero())
		if ctl.accepted && x.einval && !x.verifierReject {
			return false, nil
		}
		return false, unknownf("%s with expected attach type %s was not accepted (%s) and the control without it gave %s", progType, attachType, x.text, ctl.text)
	}
	defer p.Close()
	m, err := ebpf.NewMap(&ebpf.MapSpec{Name: "ebpf_probe", Type: ebpf.SockMap, KeySize: 4, ValueSize: 4, MaxEntries: 1})
	if err != nil {
		return false, unknownf("%s with expected attach type %s loads, but creating a sockmap for the link probe failed (%s)", progType, attachType,
			strings.SplitN(err.Error(), "\n", 2)[0])
	}
	defer m.Close()
	l, err := link.AttachRawLink(link.RawLinkOptions{Target: m.FD(), Program: p, Attach: at})
	if err == nil {
		l.Close()
		return true, nil
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, ebpf.ErrNotSupported) {
		return false, nil // Sockmap BPF_LINK_CREATE is unavailable before 6.10.
	}
	return false, unknownf("%s with expected attach type %s loads, but the sockmap link probe failed (%s)", progType, attachType,
		strings.SplitN(err.Error(), "\n", 2)[0])
}

// multiLinkAttach matches requirements.MultiLinkAttachType for KPROBE
// program type and trace_kprobe_multi/trace_uprobe_multi attach types.
func multiLinkAttach(pt ebpf.ProgramType, attachType string) bool {
	// Kprobe sessions also require fprobe link support; load can succeed
	// even without CONFIG_FPROBE, so probe link creation.
	return pt == ebpf.Kprobe && (requirements.MultiLinkAttachType(attachType) || attachType == "trace_kprobe_session")
}

// Fixed kernel test-run function for a normally uncalled multi-link probe.
const multiProbeKernelTarget = "bpf_fentry_test1"

// Dedicated never-called self-executable uprobe point. Taking its address
// in multiProbeUserOffset keeps the linker from discarding it.
//
//go:noinline
func uprobeMultiProbeTarget() {}

// multiProbeUserOffset maps this function's PC through executable
// /proc/self/maps start/file-offset evidence. Do not depend on ELF symbols,
// which go test and -s binaries may omit.
func multiProbeUserOffset() (uint64, error) {
	pc := uint64(reflect.ValueOf(uprobeMultiProbeTarget).Pointer())
	return fileOffsetOfPC(pc)
}

func fileOffsetOfPC(pc uint64) (uint64, error) {
	b, err := os.ReadFile("/proc/self/maps")
	if err != nil {
		return 0, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 6 || !strings.Contains(f[1], "x") {
			continue
		}
		var start, end, off uint64
		if _, err := fmt.Sscanf(f[0], "%x-%x", &start, &end); err != nil {
			continue
		}
		if pc < start || pc >= end {
			continue
		}
		if _, err := fmt.Sscanf(f[2], "%x", &off); err != nil {
			return 0, fmt.Errorf("/proc/self/maps: bad offset in %q", line)
		}
		exe, err := os.Readlink("/proc/self/exe")
		if err != nil {
			return 0, err
		}
		if path := strings.Join(f[5:], " "); path != exe {
			return 0, fmt.Errorf("the probe function at %#x is mapped from %q, not the executable %q", pc, path, exe)
		}
		return pc - start + off, nil
	}
	return 0, fmt.Errorf("the probe function at %#x is in no executable mapping of /proc/self/maps", pc)
}

// multiLinkVerdict returns true for nil, false only for EOPNOTSUPP (missing
// CONFIG_FPROBE/CONFIG_UPROBES) or ErrNotSupported, and Unknown for permissions,
// missing symbols, EINVAL and other failures.
func multiLinkVerdict(err error) (ok, unknown bool) {
	switch {
	case err == nil:
		return true, false
	case errors.Is(err, unix.EOPNOTSUPP) || errors.Is(err, ebpf.ErrNotSupported):
		return false, false
	}
	return false, true
}

// multiLinkProbe loads r0=0/exit with at, then immediately closes a created
// multi link: kernel probes use bpf_fentry_test1; user probes use the dedicated
// never-called /proc/self/exe point by file offset with a self-PID filter.
// Load success and enum presence do not establish link support: kernels
// without CONFIG_FPROBE can still reject link creation with EOPNOTSUPP.
// Classify via multiLinkVerdict, never infer attachment from load alone.
func multiLinkProbe(progType string, pt ebpf.ProgramType, attachType string, at ebpf.AttachType) (bool, error) {
	p, err := ebpf.NewProgram(&ebpf.ProgramSpec{Name: "ebpf_probe", Type: pt, AttachType: at, Instructions: retZero(), License: "GPL"})
	if err != nil {
		x := outcomeOf(err)
		ctl := loadProbe(pt, 0, retZero())
		if ctl.accepted && x.einval && !x.verifierReject {
			return false, nil
		}
		return false, unknownf("%s with expected attach type %s was not accepted (%s) and the control without it gave %s", progType, attachType, x.text, ctl.text)
	}
	defer p.Close()
	var l link.Link
	var where string
	if attachType == "trace_kprobe_multi" || attachType == "trace_kprobe_session" {
		// Session uses the same link and cilium's HaveBPFLinkKprobeSession probe.
		session := attachType == "trace_kprobe_session"
		where = "a kprobe.multi link on " + multiProbeKernelTarget
		if session {
			where = "a kprobe.session link on " + multiProbeKernelTarget
		}
		l, err = link.KprobeMulti(p, link.KprobeMultiOptions{Symbols: []string{multiProbeKernelTarget}, Session: session})
	} else {
		where = "a uprobe.multi link on the probe function of /proc/self/exe"
		var off uint64
		var ex *link.Executable
		if off, err = multiProbeUserOffset(); err == nil {
			where = fmt.Sprintf("a uprobe.multi link on /proc/self/exe at offset %#x", off)
			if ex, err = link.OpenExecutable("/proc/self/exe"); err == nil {
				l, err = ex.UprobeMulti(nil, p, &link.UprobeMultiOptions{Addresses: []uint64{off}, PID: uint32(os.Getpid())})
			}
		}
	}
	if err == nil {
		l.Close()
		return true, nil
	}
	if _, unknown := multiLinkVerdict(err); !unknown {
		return false, nil // Multi-link mechanism absent, e.g. CONFIG_FPROBE/CONFIG_UPROBES disabled.
	}
	return false, unknownf("%s with expected attach type %s loads, but creating %s for the link probe failed (%s)", progType, attachType, where,
		strings.SplitN(err.Error(), "\n", 2)[0])
}

func retZero() asm.Instructions { return asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()} }

// These cgroup_sock_addr recvmsg/getpeername/getsockname attach types require
// return 1..1. Probing with r0=0 would confuse a return-range rejection with
// attach-type/context incompatibility.
var retOneAttachTypes = map[string]bool{
	"cgroup_udp4_recvmsg": true, "cgroup_udp6_recvmsg": true, "cgroup_unix_recvmsg": true,
	"cgroup_inet4_getpeername": true, "cgroup_inet6_getpeername": true, "cgroup_unix_getpeername": true,
	"cgroup_inet4_getsockname": true, "cgroup_inet6_getsockname": true, "cgroup_unix_getsockname": true,
}

// probeRet returns a permitted probe result: one for 1..1 types, otherwise zero.
func probeRet(attachType string) asm.Instructions {
	if retOneAttachTypes[attachType] {
		return asm.Instructions{asm.Mov.Imm(asm.R0, 1), asm.Return()}
	}
	return retZero()
}

func (LiveCaps) HasAttachType(progType string, progTypeID int64, attachType string) (bool, error) {
	return cachedProbe(fmt.Sprintf("at/%d/%s", progTypeID, attachType), func() (bool, error) {
		pt := ebpf.ProgramType(progTypeID)
		v, found, err := AttachTypeValue(attachType)
		if err != nil {
			return false, unknownf("reading enum bpf_attach_type from the target BTF failed (%v)", err)
		}
		if !found {
			return false, nil // Target BTF does not know this attach type.
		}
		// Load modify_return/trace_iter at known targets. Acceptance is true;
		// rejection is Unknown because target/type failures are not distinguished.
		target, ok := tracingProbeTarget[attachType]
		// Only load lsm_mac at file_open: never attach a system-wide LSM link.
		if lsmTarget, lok := lsmProbeTarget[attachType]; lok && pt == ebpf.LSM {
			target, ok = lsmTarget, true
		} else if pt != ebpf.Tracing {
			ok = false
		}
		if ok {
			ps := &ebpf.ProgramSpec{Name: "ebpf_probe", Type: pt, AttachType: ebpf.AttachType(v), AttachTo: target,
				Instructions: retZero(), License: "GPL"}
			var p *ebpf.Program
			if NeedsRawLoad(ps) {
				// cilium lacks lsm_cgroup/fsession attach_btf_id resolution; use the
		// explicit raw loader in lsmcgroup.go.
				p, err = LoadRaw(ps, nil, "")
			} else {
				p, err = ebpf.NewProgram(ps)
			}
			if err == nil {
				p.Close()
				return true, nil
			}
			return false, unknownf("%s with expected attach type %s on %s was not accepted (%s)", progType, attachType, target,
				strings.SplitN(err.Error(), "\n", 2)[0])
		}
		if linkOnlyAttachType(pt, attachType) {
			// Link-only types such as perf_event load with expected_attach_type zero.
			// Query enum presence plus zero-type load, not an unrelated load value.
			ctl := loadProbe(pt, 0, retZero())
			if ctl.accepted {
				return true, nil
			}
			return false, unknownf("%s (link-only attach type %s) did not load with expected attach type 0 (%s)", progType, attachType, ctl.text)
		}
		if btfAttachTypes[pt] {
			return false, unknownf("program type %s needs a BTF attach target to load (no expected-attach-type probe)", progType)
		}
		if sockmapLinkAttach(pt) {
			// Sockmap load success also needs BPF_LINK_CREATE support. Never use
			// PROG_ATTACH as a probe or automatic fallback.
			return sockmapLinkProbe(progType, pt, attachType, ebpf.AttachType(v))
		}
		if multiLinkAttach(pt, attachType) {
			// Multi-probe load success also needs link support; missing FPROBE
			// can yield EOPNOTSUPP only at link creation.
			return multiLinkProbe(progType, pt, attachType, ebpf.AttachType(v))
		}
		x := loadProbe(pt, ebpf.AttachType(v), probeRet(attachType)) // Keep probe return within the attach type's allowed range.
		if x.accepted {
			return true, nil
		}
		ctl := loadProbe(pt, 0, retZero())
		if ctl.accepted && x.einval && !x.verifierReject {
			return false, nil
		}
		return false, unknownf("%s with expected attach type %s was not accepted (%s) and the control without it gave %s", progType, attachType, x.text, ctl.text)
	})
}

// ctxMember resolves flattened anonymous member byte offset and element size
// in target BTF STRUCT st.
func ctxMember(st, field string) (off, size int, found bool, err error) {
	spec, err := vmlinux()
	if err != nil {
		return 0, 0, false, err
	}
	var s *btf.Struct
	if err := spec.TypeByName(st, &s); err != nil {
		return 0, 0, false, err
	}
	var walk func(ms []btf.Member, base int) (int, int, bool, error)
	walk = func(ms []btf.Member, base int) (int, int, bool, error) {
		for _, m := range ms {
			o := base + int(m.Offset.Bytes())
			if m.Name == "" {
				var inner []btf.Member
				switch t := btf.UnderlyingType(m.Type).(type) {
				case *btf.Struct:
					inner = t.Members
				case *btf.Union:
					inner = t.Members
				}
				if o2, sz, ok, err := walk(inner, o); ok || err != nil {
					return o2, sz, ok, err
				}
				continue
			}
			if m.Name != field {
				continue
			}
			t := btf.UnderlyingType(m.Type)
			if a, ok := t.(*btf.Array); ok {
				t = btf.UnderlyingType(a.Type)
			}
			sz, err := btf.Sizeof(t)
			return o, sz, true, err
		}
		return 0, 0, false, nil
	}
	return walk(s.Members, 0)
}

func (LiveCaps) AllowsCtxAccess(progType string, progTypeID int64, attachType, st, field, mode string, bytes int) (bool, error) {
	return cachedProbe(fmt.Sprintf("ctx/%d/%s/%s.%s/%s/%d", progTypeID, attachType, st, field, mode, bytes), func() (bool, error) {
		pt := ebpf.ProgramType(progTypeID)
		var at ebpf.AttachType
		if attachType != "-" {
			v, found, err := AttachTypeValue(attachType)
			if err != nil {
				return false, unknownf("reading enum bpf_attach_type from the target BTF failed (%v)", err)
			}
			if !found {
				return false, unknownf("the target kernel has no attach type %s (attach_type decides)", attachType)
			}
			at = ebpf.AttachType(v)
		}
		if btfAttachTypes[pt] {
			return false, unknownf("program type %s needs a BTF attach target to load (no ctx-access probe)", progType)
		}
		off, _, found, err := ctxMember(st, field)
		if err != nil {
			return false, unknownf("reading %s from the target BTF failed (%v)", st, err)
		}
		if !found {
			return false, nil // Target UAPI context struct lacks the requested field.
		}
		var sz asm.Size
		switch bytes {
		case 1:
			sz = asm.Byte
		case 2:
			sz = asm.Half
		case 4:
			sz = asm.Word
		case 8:
			sz = asm.DWord
		default:
			return false, fmt.Errorf("ctx access width %d", bytes)
		}
		var ins asm.Instructions
		if mode == "w" {
			ins = asm.Instructions{asm.Mov.Imm(asm.R2, 0), asm.StoreMem(asm.R1, int16(off), asm.R2, sz)}
		} else {
			ins = asm.Instructions{asm.LoadMem(asm.R2, asm.R1, int16(off), sz)}
		}
		x := loadProbe(pt, at, append(ins, probeRet(attachType)...)) // Keep probe return within the attach type's allowed range.
		if x.accepted {
			return true, nil
		}
		ctl := loadProbe(pt, at, probeRet(attachType))
		if ctl.accepted && x.verifierReject {
			return false, nil
		}
		return false, unknownf("%s %s of %s.%s was not accepted (%s) and the control without it gave %s", progType, mode, st, field, x.text, ctl.text)
	})
}

// HasAttachTarget uses vmlinux metadata, not a load/attach proof. iter FUNC
// bpf_iter_<value> and LSM FUNC bpf_lsm_<value> are built-in-only, so absence
// means false. rawtp TYPEDEF btf_trace_<value> and ordinary FUNC <value> can
// live in modules, so absence is Unknown. Presence does not prove ftrace,
// fmod_ret or LSM-hook eligibility: the kernel still rejects invalid loads.
// tp checks tracefs events/<category>/<name>/id; absent/unreadable metadata is
// Unknown and actual attachment fails loudly. Other target kinds stay Unknown.
func (LiveCaps) HasAttachTarget(attachType, kind, value string) (bool, error) {
	spec, err := vmlinux()
	if err != nil {
		return false, unknownf("reading the target BTF failed (%v)", err)
	}
	switch kind {
	case "iter":
		var fn *btf.Func
		if err := spec.TypeByName("bpf_iter_"+value, &fn); err != nil {
			if errors.Is(err, btf.ErrNotFound) {
				return false, nil
			}
			return false, unknownf("looking up bpf_iter_%s failed (%v)", value, err)
		}
		return true, nil
	case "rawtp":
		var td *btf.Typedef
		if err := spec.TypeByName("btf_trace_"+value, &td); err != nil {
			return false, unknownf("btf_trace_%s is not in vmlinux BTF (%v) — a module tracepoint is not checked", value, err)
		}
		return true, nil
	case "func":
		var fn *btf.Func
		if err := spec.TypeByName(value, &fn); err != nil {
			return false, unknownf("FUNC %s is not in vmlinux BTF (%v) — a module function is not checked", value, err)
		}
		return true, nil
	case "tp": // Tracefs event ID presence means true; missing/unreadable metadata
		// (permissions, no tracefs or unavailable module event) means Unknown.
		cat, name, ok := strings.Cut(value, "/")
		if !ok || cat == "" || name == "" || strings.Contains(name, "/") || strings.Contains(value, "..") {
			return false, unknownf("tracepoint %q is not <category>/<event>", value)
		}
		var errs []string
		for _, root := range tracefsRoots {
			if _, err := os.Stat(filepath.Join(root, "events", cat, name, "id")); err == nil {
				return true, nil
			} else {
				errs = append(errs, err.Error())
			}
		}
		return false, unknownf("tracefs event %s is not readable (%s) — a module tracepoint or no tracefs is not checked", value, strings.Join(errs, "; "))
	case "lsm": // LSM hooks use built-in bpf_lsm_<hook> FUNC; absence means false.
		var fn *btf.Func
		if err := spec.TypeByName("bpf_lsm_"+value, &fn); err != nil {
			if errors.Is(err, btf.ErrNotFound) {
				return false, nil
			}
			return false, unknownf("looking up bpf_lsm_%s failed (%v)", value, err)
		}
		return true, nil
	}
	return false, unknownf("no probe yet for attach targets of kind %s", kind)
}

// tracefsRoots includes the current mount and legacy debugfs location.
var tracefsRoots = []string{"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}

// Fixed BTF targets for tracing attach-type probes.
var tracingProbeTarget = map[string]string{
	"modify_return": "bpf_modify_return_test", // net/bpf/test_run.c fmodret target set (CONFIG_NET).
	"trace_iter":    "bpf_map",                // kernel/bpf/map_iter.c bpf_iter_bpf_map.
	// fsession likewise only loads at a test-run target via the raw loader;
	// the kernel checks JIT/session support during load.
	"trace_fsession": "bpf_fentry_test1",
}

// lsmProbeTarget only loads, never attaches, at built-in integer file_open.
// lsm_cgroup uses the same hook; zero lies within its 0..1 return range.
var lsmProbeTarget = map[string]string{"lsm_mac": "file_open", "lsm_cgroup": "file_open"}
