//go:build linux

package kload

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/yuskesh/go-bpf-mlir/requirements"
	"golang.org/x/sys/unix"
)

type helperTargetAnswer struct {
	diffs []string
	err   error
}
type helperTargetCache struct {
	mu      sync.Mutex
	answers map[string]helperTargetAnswer
}

var typedHelperMemo helperTargetCache

func (m *helperTargetCache) query(identity, pt string, id int64, h requirements.HelperTarget, probe func() ([]string, error)) ([]string, error) {
	key := identity + "\x00" + requirements.HelperTargetKey(pt, id, h)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.answers == nil {
		m.answers = map[string]helperTargetAnswer{}
	}
	a, ok := m.answers[key]
	if !ok {
		a.diffs, a.err = probe()
		a.diffs = append([]string{}, a.diffs...)
		m.answers[key] = a
	}
	return append([]string{}, a.diffs...), a.err
}

// CheckHelperTarget only accepts a successful well-typed load at the requested
// target. Unlike the generic prototype probe, EACCES is never presence.
func (LiveCaps) CheckHelperTarget(pt string, id int64, h requirements.HelperTarget) ([]string, error) {
	if pt != "tracing" || id != int64(ebpf.Tracing) || h.Helper != "d_path" || h.HelperID != int64(asm.FnDPath) || h.AttachType != "trace_fentry" || h.ArgIndex != 0 || h.ArgType != "path" || h.Target == "" {
		return []string{"unsupported target-specific helper profile"}, nil
	}
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil || strings.TrimSpace(string(boot)) == "" {
		return nil, fmt.Errorf("helper_target boot identity unavailable: %v: %w", err, requirements.ErrUnknown)
	}
	p := requirements.CurrentPrivilege()
	if p.CapEff == "" {
		return nil, fmt.Errorf("helper_target probe privilege unavailable: %w", requirements.ErrUnknown)
	}
	identity := fmt.Sprintf("%s/%d/%s", strings.TrimSpace(string(boot)), p.UID, p.CapEff)
	return typedHelperMemo.query(identity, pt, id, h, func() ([]string, error) {
		return runHelperTargetProbe(h, LiveCaps{}.CheckFuncArgs, func(spec *ebpf.ProgramSpec) (io.Closer, error) {
			p, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch})
			if err != nil {
				return nil, err
			}
			return p, nil
		})
	})
}

// The ctx's first slot holds struct path*. Initialize all 64 destination bytes
// and branch around a NULL path. No helper other than d_path is involved.
func helperTargetProbeSpec(h requirements.HelperTarget) *ebpf.ProgramSpec {
	ins := asm.Instructions{asm.LoadMem(asm.R1, asm.R1, 0, asm.DWord), asm.JEq.Imm(asm.R1, 0, "done"), asm.Mov.Imm(asm.R0, 0)}
	for off := int16(-64); off < 0; off += 8 {
		ins = append(ins, asm.StoreMem(asm.RFP, off, asm.R0, asm.DWord))
	}
	ins = append(ins, asm.Mov.Reg(asm.R2, asm.RFP), asm.Add.Imm(asm.R2, -64), asm.Mov.Imm(asm.R3, 64), asm.FnDPath.Call(), asm.Mov.Imm(asm.R0, 0).WithSymbol("done"), asm.Return())
	return &ebpf.ProgramSpec{Name: "typed_dpath", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: h.Target, License: "GPL", Instructions: ins}
}

func runHelperTargetProbe(h requirements.HelperTarget, check func(string, []string) ([]string, error), load func(*ebpf.ProgramSpec) (io.Closer, error)) ([]string, error) {
	d, err := check(h.Target, []string{"path"})
	if err != nil || len(d) > 0 {
		return d, err
	}
	p, err := load(helperTargetProbeSpec(h))
	if err == nil {
		if p == nil {
			return nil, fmt.Errorf("helper_target load returned no owned program")
		}
		if err := p.Close(); err != nil {
			return nil, fmt.Errorf("helper_target close: %w", err)
		}
		return nil, nil
	}
	var ve *ebpf.VerifierError
	if errors.As(err, &ve) && errors.Is(err, unix.EINVAL) && logContainsAll(ve.Log, "helper call is not allowed in probe") {
		return []string{fmt.Sprintf("helper d_path is not allowed at trace_fentry/%s: %s", h.Target, strings.Join(ve.Log, "\n"))}, nil
	}
	// Permission, target resolution, malformed argument/probe, missing helper and
	// unrelated verifier failures do not establish this exact target's permission.
	detail := err.Error()
	if ve != nil {
		// VerifierError.Error abbreviates the log and can omit processed0. Keep
		// the complete observation in the recorded Unknown, just as for a denial.
		detail = fmt.Sprintf("errno %v; verifier log:\n%s", ve.Cause, strings.Join(ve.Log, "\n"))
	}
	return nil, fmt.Errorf("helper_target trace_fentry/%s load was not accepted: %s: %w", h.Target, detail, requirements.ErrUnknown)
}
