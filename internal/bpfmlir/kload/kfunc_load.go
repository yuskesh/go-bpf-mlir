//go:build linux

package kload

import (
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"github.com/yuskesh/go-bpf-mlir/internal/bpfmlir/btfexact"
)

type kfuncRecipeProto struct {
	ret  string
	args []string
}

var kfuncRecipeProtos = map[string]kfuncRecipeProto{
	"bpf_task_from_pid":     {"ptr:task_struct", []string{"i32"}},
	"bpf_task_acquire":      {"ptr:task_struct", []string{"ptr:task_struct"}},
	"bpf_task_release":      {"void", []string{"ptr:task_struct"}},
	"bpf_session_is_return": {"bool", []string{"ptr:void"}},
	"bpf_session_cookie":    {"ptr:u64", []string{"ptr:void"}},
}

type kfuncLoadDeps struct {
	resolve func(name, ret string, args []string) (int32, error)
	load    func(*ebpf.ProgramSpec) (io.Closer, error)
	arena   arenaKfuncDeps // the arena recipe (kfunc_arena.go)
}

// HasKfuncLoad creates no attach or test run. Only the arena recipe creates a map:
// one arena map, never mmapped. Refuse unsupported profiles before reading/loading BTF.
func (LiveCaps) HasKfuncLoad(p requirements.KfuncProfile, name, ret string, args []string) (bool, error) {
	return forwardKfuncLoad(p, name, ret, args, liveKfuncLoadDeps())
}

func forwardKfuncLoad(p requirements.KfuncProfile, name, ret string, args []string, d kfuncLoadDeps) (bool, error) {
	return loadKfuncProfile(p, name, ret, append([]string{}, args...), d)
}

// Construction performs no reader/syscall work; closures execute only in
// resolve/load after the guard.
func liveKfuncLoadDeps() kfuncLoadDeps {
	return kfuncLoadDeps{
		resolve: func(n, r string, a []string) (int32, error) {
			s, err := vmlinux()
			return resolveKfuncLoadRead(s, err, n, r, a)
		},
		load: func(ps *ebpf.ProgramSpec) (io.Closer, error) {
			p, err := ebpf.NewProgramWithOptions(ps, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch | ebpf.LogLevelStats, LogSizeStart: 1024 * 1024})
			return kfuncProgramHandle(p, err)
		},
		arena: liveArenaKfuncDeps(),
	}
}

// Preserve a nil interface on constructor errors; *Program(nil) is non-nil as io.Closer.
func kfuncProgramHandle(p *ebpf.Program, err error) (io.Closer, error) {
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, errors.New("constructor returned no program")
	}
	return p, nil
}

func resolveKfuncLoadRead(s *btf.Spec, err error, name, ret string, args []string) (int32, error) {
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, os.ErrPermission) || errors.Is(err, ebpf.ErrNotSupported) {
			return 0, fmt.Errorf("kfunc %s BTF unavailable: %w: %w", name, err, requirements.ErrUnknown)
		}
		return 0, fmt.Errorf("kfunc %s target BTF: %w", name, err)
	}
	return resolveKfuncLoad(s, name, ret, args)
}

func resolveKfuncLoad(s *btf.Spec, name, ret string, args []string) (int32, error) {
	if s == nil {
		return 0, fmt.Errorf("kfunc %s BTF unavailable: %w", name, requirements.ErrUnknown)
	}
	var fn *btf.Func
	if err := btfexact.TypeByName(s, name, &fn); err != nil {
		return 0, fmt.Errorf("kfunc dependency %s: %v: %w", name, err, requirements.ErrUnknown)
	}
	proto, ok := fn.Type.(*btf.FuncProto)
	if !ok {
		return 0, fmt.Errorf("kfunc dependency %s has no FUNC_PROTO: %w", name, requirements.ErrUnknown)
	}
	if diff := CompareKfuncProto(name, proto, ret, args); len(diff) != 0 {
		return 0, fmt.Errorf("kfunc dependency %s prototype: %s: %w", name, strings.Join(diff, "; "), requirements.ErrUnknown)
	}
	id, err := s.TypeID(fn)
	if err != nil || id == 0 || uint64(id) > math.MaxInt32 {
		return 0, fmt.Errorf("kfunc dependency %s invalid vmlinux FUNC ID: %w", name, requirements.ErrUnknown)
	}
	return int32(id), nil
}

func kfuncInitialSpec(p requirements.KfuncProfile) (*ebpf.ProgramSpec, error) {
	unknown := func() (*ebpf.ProgramSpec, error) {
		return nil, fmt.Errorf("no finite load-only recipe for initial profile %s: %w", p.Kind, requirements.ErrUnknown)
	}
	// Raw fsession transport and struct_ops member recipes are unsupported.
	// In particular, do not introduce a path that loads host sched_ext programs.
	if p.Recipe != "kfunc-v1" || p.ContextIdentity == "" || p.Kind == "fsession" || p.Kind == "struct_ops" {
		return unknown()
	}
	typ := ebpf.ProgramType(p.ProgTypeID)
	at := ebpf.AttachNone
	section := p.Kind
	typeName := p.Kind
	targetKind := "none"
	flags := uint32(0)
	switch p.Kind {
	case "syscall":
		typ = ebpf.Syscall
		flags = 16
		if p.AttachType != "-" {
			return unknown()
		}
	case "xdp":
		typ = ebpf.XDP
		at = ebpf.AttachXDP
		if p.AttachType != "xdp" {
			return unknown()
		}
	case "sched_cls":
		typ = ebpf.SchedCLS
		switch p.AttachType {
		case "tcx_ingress":
			at = ebpf.AttachTCXIngress
			section = "tcx/ingress"
		case "tcx_egress":
			at = ebpf.AttachTCXEgress
			section = "tcx/egress"
		case "netkit_primary":
			at = ebpf.AttachNetkitPrimary
			section = "netkit/primary"
		case "netkit_peer":
			at = ebpf.AttachNetkitPeer
			section = "netkit/peer"
		default:
			return unknown()
		}
	case "cgroup_skb":
		typ = ebpf.CGroupSKB
		targetKind = "cgroup"
		switch p.AttachType {
		case "cgroup_inet_ingress":
			at = ebpf.AttachCGroupInetIngress
			section = "cgroup_skb/ingress"
		case "cgroup_inet_egress":
			at = ebpf.AttachCGroupInetEgress
			section = "cgroup_skb/egress"
		default:
			return unknown()
		}
	case "tracepoint":
		typ = ebpf.TracePoint
		targetKind = "tp"
		if p.AttachType != "-" || strings.Count(p.Target, "/") != 1 || strings.HasPrefix(p.Target, "/") || strings.HasSuffix(p.Target, "/") || strings.ContainsAny(p.Target, " \t\n:") {
			return unknown()
		}
		section = "tracepoint/" + p.Target
	case "raw_tp":
		typ = ebpf.RawTracepoint
		typeName = "raw_tracepoint"
		targetKind = "rawtp"
		if p.AttachType != "-" || p.Target == "" || strings.ContainsAny(p.Target, "/ \t\n:") {
			return unknown()
		}
		section = "raw_tp/" + p.Target
	case "perf_event":
		typ = ebpf.PerfEvent
		targetKind = "perf"
		if p.AttachType != "-" || p.Target != "" {
			return unknown()
		}
	case "lsm":
		typ = ebpf.LSM
		at = ebpf.AttachLSMMac
		targetKind = "lsm"
		if p.AttachType != "lsm_mac" || p.Target == "" || strings.ContainsAny(p.Target, "/ \t\n:") {
			return unknown()
		}
		section = "lsm/" + p.Target
	case "cgroup_sock":
		typ = ebpf.CGroupSock
		targetKind = "cgroup"
		at = ebpf.AttachCGroupInetSockCreate
		if p.AttachType != "cgroup_inet_sock_create" {
			return unknown()
		}
		section = "cgroup/sock_create"
	case "cgroup_device":
		typ = ebpf.CGroupDevice
		targetKind = "cgroup"
		at = ebpf.AttachCGroupDevice
		if p.AttachType != "cgroup_device" {
			return unknown()
		}
		section = "cgroup/dev"
	case "cgroup_sock_addr":
		typ = ebpf.CGroupSockAddr
		targetKind = "cgroup"
		at = ebpf.AttachCGroupInet4Connect
		if p.AttachType != "cgroup_inet4_connect" {
			return unknown()
		}
		section = "cgroup/connect4"
	case "cgroup_sockopt":
		typ = ebpf.CGroupSockopt
		targetKind = "cgroup"
		at = ebpf.AttachCGroupGetsockopt
		if p.AttachType != "cgroup_getsockopt" {
			return unknown()
		}
		section = "cgroup/getsockopt"
	case "cgroup_sysctl":
		typ = ebpf.CGroupSysctl
		targetKind = "cgroup"
		at = ebpf.AttachCGroupSysctl
		if p.AttachType != "cgroup_sysctl" {
			return unknown()
		}
		section = "cgroup/sysctl"
	case "sock_ops":
		typ = ebpf.SockOps
		targetKind = "cgroup"
		at = ebpf.AttachCGroupSockOps
		if p.AttachType != "cgroup_sock_ops" {
			return unknown()
		}
		section = "sockops"
	case "tp_btf", "fentry", "fexit", "iter", "fmod_ret", "kprobe_session":
		typ = ebpf.Tracing
		typeName = "tracing"
		targetKind = "func"
		if p.Target == "" || strings.ContainsAny(p.Target, "/ \t\n:") {
			return unknown()
		}
		section = p.Kind + "/" + p.Target
		switch p.Kind {
		case "tp_btf":
			at = ebpf.AttachTraceRawTp
			targetKind = "tp"
			if p.AttachType != "trace_raw_tp" {
				return unknown()
			}
		case "fentry":
			at = ebpf.AttachTraceFEntry
			if p.AttachType != "trace_fentry" {
				return unknown()
			}
		case "fexit":
			at = ebpf.AttachTraceFExit
			if p.AttachType != "trace_fexit" {
				return unknown()
			}
		case "iter":
			at = ebpf.AttachTraceIter
			targetKind = "iter"
			if p.AttachType != "trace_iter" {
				return unknown()
			}
		case "fmod_ret":
			at = ebpf.AttachModifyReturn
			if p.AttachType != "modify_return" {
				return unknown()
			}
		case "kprobe_session":
			typ = ebpf.Kprobe
			typeName = "kprobe"
			at = ebpf.AttachTraceKprobeSession
			section = "kprobe.session/" + p.Target
			if p.AttachType != "trace_kprobe_session" {
				return unknown()
			}
		}
	default:
		return unknown()
	}
	if int64(typ) != p.ProgTypeID || typeName != p.ProgType || p.Section != section || p.TargetKind != targetKind || p.ProgFlags != flags {
		return unknown()
	}
	if targetKind == "none" || targetKind == "ingress" || targetKind == "egress" || targetKind == "cgroup" {
		if p.Target != "" {
			return unknown()
		}
	}
	return &ebpf.ProgramSpec{Name: "kfunc_probe", Type: typ, AttachType: at, AttachTo: p.Target, Flags: flags, License: "GPL"}, nil
}

func loadKfuncProfile(p requirements.KfuncProfile, name, ret string, args []string, d kfuncLoadDeps) (bool, error) {
	ps, err := kfuncInitialSpec(p)
	if err != nil {
		return false, err
	}
	if isArenaKfunc(name) { // same place as bml's bml_live_kfunc_load: after the initial profile, before the recipe table
		return loadArenaKfunc(p, name, ret, args, d.arena)
	}
	proto, known := kfuncRecipeProtos[name]
	if !known || proto.ret != ret || !reflect.DeepEqual(proto.args, args) {
		return false, fmt.Errorf("no strict kfunc recipe for %s: %w", name, requirements.ErrUnknown)
	}
	session := strings.HasPrefix(name, "bpf_session_")
	if session && p.Kind != "kprobe_session" {
		return false, fmt.Errorf("session recipe needs original kprobe_session context: %w", requirements.ErrUnknown)
	}
	deps := []string{name}
	if !session {
		deps = []string{"bpf_task_from_pid", "bpf_task_release"}
		if name == "bpf_task_acquire" {
			deps = []string{"bpf_task_from_pid", "bpf_task_acquire", "bpf_task_release"}
		}
	}
	ids := map[string]int32{}
	for _, n := range deps {
		s := kfuncRecipeProtos[n]
		id, e := d.resolve(n, s.ret, append([]string{}, s.args...))
		if e != nil {
			return false, e
		}
		if id <= 0 {
			return false, fmt.Errorf("invalid resolved kfunc ID for %s: %w", n, requirements.ErrUnknown)
		}
		ids[n] = id
	}
	call := func(n string) asm.Instruction {
		return asm.Instruction{OpCode: asm.Call.Op(asm.ImmSource), Src: asm.PseudoKfuncCall, Constant: int64(ids[n])}
	}
	retVal := int32(0)
	if p.Kind == "xdp" {
		retVal = 2
	}
	if p.Kind == "cgroup_skb" {
		retVal = 1
	}
	exit := asm.Mov.Imm(asm.R0, retVal).WithSymbol("done")
	if session {
		ps.Instructions = asm.Instructions{call(name), exit, asm.Return()}
	} else {
		ps.Instructions = asm.Instructions{asm.Mov.Imm(asm.R1, int32(os.Getpid())), call("bpf_task_from_pid"), asm.Mov.Reg(asm.R6, asm.R0), asm.JEq.Imm(asm.R6, 0, "done")}
		if name == "bpf_task_acquire" {
			ps.Instructions = append(ps.Instructions, asm.Mov.Reg(asm.R1, asm.R6), call("bpf_task_acquire"), asm.Mov.Reg(asm.R7, asm.R0), asm.JEq.Imm(asm.R7, 0, "release_original"), asm.Mov.Reg(asm.R1, asm.R7), call("bpf_task_release"))
		}
		ps.Instructions = append(ps.Instructions, asm.Mov.Reg(asm.R1, asm.R6).WithSymbol("release_original"), call("bpf_task_release"), exit, asm.Return())
	}
	prog, err := d.load(ps)
	if err != nil {
		if prog != nil {
			if e := prog.Close(); e != nil {
				return false, fmt.Errorf("failed load resource close: %w", e)
			}
		}
		return classifyKfuncLoadError(name, err)
	}
	if prog == nil {
		return false, fmt.Errorf("load returned no program: %w", requirements.ErrUnknown)
	}
	if err := prog.Close(); err != nil {
		return false, fmt.Errorf("kfunc probe close: %w", err)
	}
	return true, nil
}

func kfuncVerifierLog(err error) string {
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return ""
	}
	return fmt.Sprintf("%+v", ve)
}
func classifyKfuncLoadError(name string, err error) (bool, error) {
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) {
		want := "calling kernel function " + name + " is not allowed"
		named := false
		for _, line := range ve.Log {
			line = strings.TrimSpace(line)
			if line == want {
				named = true
			} else if strings.Contains(line, "calling kernel function ") && strings.Contains(line, " is not allowed") {
				return false, fmt.Errorf("different callee denial: %s: %w", kfuncVerifierLog(err), requirements.ErrUnknown)
			}
		}
		if named {
			return false, nil
		}
	}
	return false, fmt.Errorf("kfunc load result does not establish named permission denial: %s: %w", nonemptyKfuncLog(err), requirements.ErrUnknown)
}
func nonemptyKfuncLog(err error) string {
	if full := kfuncVerifierLog(err); full != "" {
		return full
	}
	return err.Error()
}
