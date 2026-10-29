package requirements

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"strings"
)

// Finite section-to-initial-loader-profile mapping. Never default unknown flags to zero.
type kfuncProfileRow struct {
	kind, section, typ, attach, reqAttach, targetKind string
	id                                                int64
	flags                                             uint32
	prefix                                            bool
}

var kfuncProfileRows = []kfuncProfileRow{
	{"syscall", "syscall", "syscall", "-", "syscall", "none", 31, 16, false},
	{"xdp", "xdp", "xdp", "xdp", "", "none", 6, 0, false},
	{"sched_cls", "tcx/ingress", "sched_cls", "tcx_ingress", "tcx", "ingress", 3, 0, false},
	{"sched_cls", "tcx/egress", "sched_cls", "tcx_egress", "tcx", "egress", 3, 0, false},
	{"cgroup_skb", "cgroup_skb/ingress", "cgroup_skb", "cgroup_inet_ingress", "cgroup_inet_ingress", "cgroup", 8, 0, false},
	{"cgroup_skb", "cgroup_skb/egress", "cgroup_skb", "cgroup_inet_egress", "cgroup_inet_egress", "cgroup", 8, 0, false},
	{"tp_btf", "tp_btf/", "tracing", "trace_raw_tp", "trace_raw_tp", "tp_btf", 26, 0, true},
	{"fentry", "fentry/", "tracing", "trace_fentry", "trace_fentry", "func", 26, 0, true},
	{"fexit", "fexit/", "tracing", "trace_fexit", "trace_fexit", "func", 26, 0, true},
	{"fmod_ret", "fmod_ret/", "tracing", "modify_return", "trace_fmod_ret", "func", 26, 0, true},
	{"iter", "iter/", "tracing", "trace_iter", "trace_iter", "iter", 26, 0, true},
	{"kprobe_session", "kprobe.session/", "kprobe", "trace_kprobe_session", "trace_kprobe_session", "func", 2, 0, true},
	{"fsession", "fsession/", "tracing", "trace_fsession", "trace_fsession", "func", 26, 0, true},
	{"tracepoint", "tracepoint/", "tracepoint", "-", "trace_tp", "tp", 5, 0, true},
	{"raw_tp", "raw_tp/", "raw_tracepoint", "-", "raw_tp", "rawtp", 17, 0, true},
	{"perf_event", "perf_event", "perf_event", "-", "trace_perf", "perf", 7, 0, false},
	{"lsm", "lsm/", "lsm", "lsm_mac", "lsm_mac", "lsm", 29, 0, true},
	{"cgroup_sock", "cgroup/sock_create", "cgroup_sock", "cgroup_inet_sock_create", "cgroup_inet_sock_create", "cgroup", 9, 0, false},
	{"cgroup_device", "cgroup/dev", "cgroup_device", "cgroup_device", "cgroup_device", "cgroup", 15, 0, false},
	{"cgroup_sock_addr", "cgroup/connect4", "cgroup_sock_addr", "cgroup_inet4_connect", "cgroup_inet4_connect", "cgroup", 18, 0, false},
	{"cgroup_sockopt", "cgroup/getsockopt", "cgroup_sockopt", "cgroup_getsockopt", "cgroup_getsockopt", "cgroup", 25, 0, false},
	{"cgroup_sysctl", "cgroup/sysctl", "cgroup_sysctl", "cgroup_sysctl", "cgroup_sysctl", "cgroup", 23, 0, false},
	{"sock_ops", "sockops", "sock_ops", "cgroup_sock_ops", "cgroup_sock_ops", "cgroup", 13, 0, false},
}

type kfuncProfileSnapshot struct {
	profile  KfuncProfile
	snapshot string
	reason   string
}

func profileSnapshot(req *Requirements, symbol string) (string, Program, []Attach, error) {
	var p Program
	n := 0
	for _, x := range req.Programs {
		if x.Symbol == symbol {
			p = x
			n++
		}
	}
	if n != 1 {
		return "", p, nil, fmt.Errorf("%w: entry program is not unique", ErrUnknown)
	}
	var as []Attach
	for _, a := range req.Attaches {
		if a.Program == symbol {
			as = append(as, a)
		}
	}
	b, _ := json.Marshal(struct {
		Program  Program
		Attaches []Attach
	}{p, as})
	return string(b), p, as, nil
}

func deriveKfuncProfiles(f *elf.File, req *Requirements) map[string]kfuncProfileSnapshot {
	out := make(map[string]kfuncProfileSnapshot)
	syms, symErr := f.Symbols()
	for _, k := range req.Kfuncs {
		if _, exists := out[k.Program]; exists {
			continue
		}
		snap, p, as, err := profileSnapshot(req, k.Program)
		x := kfuncProfileSnapshot{snapshot: snap}
		var found []elf.Symbol
		for _, s := range syms {
			if s.Name == k.Program && elf.ST_TYPE(s.Info) == elf.STT_FUNC && s.Section != elf.SHN_UNDEF {
				found = append(found, s)
			}
		}
		if err != nil || symErr != nil || len(found) != 1 {
			x.reason = "actual ELF entry FUNC is unavailable or not unique"
		} else {
			s := found[0]
			if int(s.Section) >= len(f.Sections) || s.Section >= elf.SHN_LORESERVE {
				x.reason = "actual ELF entry section is unavailable"
			} else {
				sec := f.Sections[s.Section]
				namedSections := 0
				for _, candidate := range f.Sections {
					if candidate.Name == sec.Name {
						namedSections++
					}
				}
				entries := 0
				for _, candidate := range syms {
					if candidate.Section == s.Section && elf.ST_TYPE(candidate.Info) == elf.STT_FUNC && candidate.Value == 0 {
						entries++
					}
				}
				if namedSections != 1 || entries != 1 || sec.Type != elf.SHT_PROGBITS || sec.Flags&elf.SHF_EXECINSTR == 0 || s.Size == 0 || s.Value != 0 || s.Size%8 != 0 || s.Size > sec.Size {
					x.reason = "actual ELF entry bounds are invalid"
				} else {
					x.profile, err = canonicalKfuncProfile(sec.Name, p, as)
					if err != nil {
						x.reason = err.Error()
					}
				}
			}
		}
		out[k.Program] = x
	}
	return out
}

func canonicalKfuncProfile(section string, p Program, as []Attach) (KfuncProfile, error) {
	for _, r := range kfuncProfileRows {
		target := ""
		if r.prefix {
			if !strings.HasPrefix(section, r.section) {
				continue
			}
			target = strings.TrimPrefix(section, r.section)
			badTarget := target == "" || strings.ContainsAny(target, " \t\n:")
			if r.kind == "tracepoint" {
				badTarget = badTarget || strings.Count(target, "/") != 1 || strings.HasPrefix(target, "/") || strings.HasSuffix(target, "/")
			} else {
				badTarget = badTarget || strings.Contains(target, "/")
			}
			if badTarget {
				continue
			}
		} else if section != r.section {
			continue
		}
		if p.ProgType != r.typ || p.ProgTypeID != r.id {
			break
		}
		if r.reqAttach == "" {
			if len(as) != 0 {
				break
			}
		} else {
			if len(as) != 1 {
				break
			}
			// Generic modify_return uses the same section/type/flags/target. Keep
			// its raw Generic identity in ContextIdentity and the snapshot; do not
			// extend this equivalence to other kinds.
			genericFmodRet := r.kind == "fmod_ret" && as[0].Generic && as[0].AttachType == "modify_return" && as[0].TargetKind == "func" && as[0].TargetValue == target && as[0].Target == "func:"+target
			if as[0].AttachType != r.reqAttach && !genericFmodRet {
				break
			}
			want := target
			if !r.prefix {
				want = r.targetKind
			}
			if r.kind == "iter" || r.kind == "kprobe_session" || r.kind == "fsession" || r.kind == "raw_tp" || r.kind == "lsm" {
				want = r.targetKind + ":" + target
			}
			if as[0].Target != want && !genericFmodRet {
				break
			}
		}
		ctx := r.kind
		if len(as) == 1 {
			a := as[0]
			a.Program = ""
			b, _ := json.Marshal(a)
			ctx = string(b)
		}
		targetKind := r.targetKind
		if r.kind == "sched_cls" {
			targetKind = "none"
		}
		if r.kind == "tp_btf" {
			targetKind = "tp"
		}
		return KfuncProfile{Kind: r.kind, Section: section, ProgType: r.typ, ProgTypeID: r.id, ProgFlags: r.flags, AttachType: r.attach, TargetKind: targetKind, Target: target, ContextIdentity: ctx, Recipe: "kfunc-v1"}, nil
	}
	return KfuncProfile{}, fmt.Errorf("%w: section/program/attach has no canonical initial profile", ErrUnknown)
}

func kfuncProfileFor(req *Requirements, symbol string) (KfuncProfile, error) {
	x, ok := req.kfuncProfiles[symbol]
	if !ok {
		return KfuncProfile{}, fmt.Errorf("%w: kfunc profile is not actual-ELF-derived", ErrUnknown)
	}
	if x.reason != "" {
		return KfuncProfile{}, fmt.Errorf("%w: %s", ErrUnknown, x.reason)
	}
	snap, _, _, err := profileSnapshot(req, symbol)
	if err != nil || snap != x.snapshot {
		return KfuncProfile{}, fmt.Errorf("%w: program/attach changed since actual ELF derivation", ErrUnknown)
	}
	return x.profile, nil
}

// KfuncProfile returns the actual ELF's initial profile for exactly one named
// kfunc row. Do not infer missing/duplicate rows, hand-parsed profiles or changed
// Program/Attach entries. Callers must preserve the profile if they later
// override ProgramSpec.
func (req *Requirements) KfuncProfile(program, name string) (KfuncProfile, error) {
	if req == nil {
		return KfuncProfile{}, fmt.Errorf("%w: no requirements", ErrUnknown)
	}
	count := 0
	for _, k := range req.Kfuncs {
		if k.Program == program && k.Name == name {
			count++
		}
	}
	if count != 1 {
		return KfuncProfile{}, fmt.Errorf("%w: named kfunc row is absent or not unique", ErrUnknown)
	}
	return kfuncProfileFor(req, program)
}
