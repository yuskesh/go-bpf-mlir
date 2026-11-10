//go:build linux

package kload

// CheckSleepable: can a program of this type be loaded with
// BPF_F_SLEEPABLE? The kernel refuses in three separable ways and only the
// first is "the type cannot be sleepable":
//
//   - "Program of this type cannot be sleepable" (can_be_sleepable) — false,
//     but only once a control load of the same program without the flag
//     succeeded (so the refusal is about the flag, not the target or rights);
//   - "<function> is not sleepable" — the attach target is not on the
//     error-injection / allow list: the type itself may be fine, so Unknown;
//   - EPERM / EACCES / an absent target / anything else — Unknown.
//
// Unknown never blocks (the kernel refuses a bad sleepable load loudly) and is
// never turned into false.

import (
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// sleepableLoad is the last boundary before the SDK: it loads spec and returns
// the program (to close) or the load error (a *ebpf.VerifierError carries the log).
type sleepableLoad func(spec *ebpf.ProgramSpec) (io.Closer, error)

// newSleepableProgram is the last SDK boundary (replaced only by tests, which restore it).
var newSleepableProgram = ebpf.NewProgramWithOptions

func ciliumSleepableLoad(spec *ebpf.ProgramSpec) (io.Closer, error) {
	p, err := newSleepableProgram(spec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch})
	if err != nil {
		return nil, err
	}
	return p, nil
}

// sleepableProbeTarget is a syscall entry: arch syscalls are on the error-injection
// list, which is what lets a fentry attach sleepable. Empty when the arch is unknown.
func sleepableProbeTarget(goarch string) string {
	switch goarch {
	case "amd64":
		return "__x64_sys_getpgid"
	case "arm64":
		return "__arm64_sys_getpgid"
	}
	return ""
}

// CheckSleepable implements requirements.SleepableCaps for the live kernel.
func (LiveCaps) CheckSleepable(programType, attachType string) (bool, error) {
	return probeSleepable(programType, attachType, sleepableProbeTarget(runtime.GOARCH), ciliumSleepableLoad)
}

func probeSleepable(programType, attachType, target string, load sleepableLoad) (have bool, result error) {
	unknown := func(format string, args ...any) (bool, error) {
		return false, fmt.Errorf("sleepable probe (%s/%s): %s: %w", programType, attachType, fmt.Sprintf(format, args...), requirements.ErrUnknown)
	}
	if programType != "tracing" || attachType != "trace_fentry" {
		return unknown("no probe for this pair")
	}
	if target == "" {
		return unknown("no sleepable-capable probe target for this architecture")
	}
	spec := func(flags uint32) *ebpf.ProgramSpec {
		return &ebpf.ProgramSpec{
			Name: "ebpf_slp_probe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceFEntry, AttachTo: target, Flags: flags, License: "GPL",
			Instructions: asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()},
		}
	}
	closeProbe := func(c io.Closer, what string) {
		if err := c.Close(); err != nil {
			have = false
			result = errors.Join(result, fmt.Errorf("close the %s sleepable probe program: %w: %w", what, err, requirements.ErrUnknown))
		}
	}
	p, err := load(spec(unix.BPF_F_SLEEPABLE))
	if err == nil {
		closeProbe(p, "accepted")
		if result != nil {
			return false, result
		}
		return true, nil
	}
	sleepErr := err
	control, cerr := load(spec(0))
	if cerr != nil {
		return false, fmt.Errorf("sleepable probe (%s/%s): the sleepable load failed (%w) and so did the control load without the flag (%w): %w", programType, attachType, sleepErr, cerr, requirements.ErrUnknown)
	}
	closeProbe(control, "control")
	if result != nil {
		return false, errors.Join(fmt.Errorf("sleepable probe (%s/%s): the sleepable load was refused (%w)", programType, attachType, sleepErr), result)
	}
	var verr *ebpf.VerifierError
	if errors.As(sleepErr, &verr) && logHasLine(verr.Log, "Program of this type cannot be sleepable") {
		return false, nil
	}
	return false, fmt.Errorf("sleepable probe (%s/%s): the sleepable load was refused for another reason than the program type (%w) while the control load succeeded: %w", programType, attachType, sleepErr, requirements.ErrUnknown)
}

func logHasLine(log []string, sub string) bool {
	for _, l := range log {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

var _ requirements.SleepableCaps = LiveCaps{}
