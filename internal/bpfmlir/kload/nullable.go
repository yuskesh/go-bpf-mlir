//go:build linux

package kload

// Probe whether tp_btf arguments are marked PTR_MAYBE_NULL. Kernel
// raw_tp_null_args (and newer __nullable names) drives this, not BTF alone.
// Older kernels without marking can silently return zero through PROBE_MEM.
// Load N with unchecked sched_pi_setprio argument 1 (nullable) and control C
// with unchecked sched_process_fork argument 0 (not nullable). C must accept,
// otherwise Unknown. N rejecting with or_null means marked; accepting means
// unmarked; other results are Unknown.

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// NullableProbe retains one probe's observations for developer reporting.
type NullableProbe struct {
	Nullable, Control string // accept or the relevant verifier/load failure reason.
}

var (
	nullableOnce  sync.Once
	nullableMarks bool
	nullableErr   error
)

// MarksNullableTPArgs implements NullableArgCaps with one probe per process.
func (LiveCaps) MarksNullableTPArgs() (bool, error) {
	nullableOnce.Do(func() { nullableMarks, _, nullableErr = ProbeNullableArgs() })
	return nullableMarks, nullableErr
}

// ProbeNullableArgs runs the load pair and returns its decision and observations.
func ProbeNullableArgs() (bool, NullableProbe, error) {
	var rec NullableProbe
	ctl, cerr := loadNullableProbe("sched_process_fork", 0)
	rec.Control = ctl
	if cerr != nil {
		return false, rec, cerr
	}
	if ctl != "accept" {
		return false, rec, fmt.Errorf("the control (sched_process_fork argument 0) was not accepted (%s) — the probe cannot tell: %w", ctl, requirements.ErrUnknown)
	}
	nul, nerr := loadNullableProbe("sched_pi_setprio", 1)
	rec.Nullable = nul
	if nerr != nil {
		return false, rec, nerr
	}
	switch {
	case nul == "accept":
		return false, rec, nil
	case strings.Contains(nul, "or_null"):
		return true, rec, nil
	}
	return false, rec, fmt.Errorf("the NULL-able read was rejected for another reason (%s): %w", nul, requirements.ErrUnknown)
}

// loadNullableProbe reads four bytes through argument arg without a null
// check. Return accept or a verifier line. Failures before verification
// (permissions/target resolution) are Unknown errors.
func loadNullableProbe(tp string, arg int16) (string, error) {
	prog, err := ebpf.NewProgram(&ebpf.ProgramSpec{
		Name: "nullable_probe", Type: ebpf.Tracing, AttachType: ebpf.AttachTraceRawTp, AttachTo: tp, License: "GPL",
		Instructions: asm.Instructions{
			asm.LoadMem(asm.R2, asm.R1, arg*8, asm.DWord),
			asm.LoadMem(asm.R0, asm.R2, 0, asm.Word),
			asm.Mov.Imm(asm.R0, 0),
			asm.Return(),
		},
	})
	if err == nil {
		prog.Close()
		return "accept", nil
	}
	var ve *ebpf.VerifierError
	if !errors.As(err, &ve) {
		return "", fmt.Errorf("nullable-argument probe (%s) did not reach the verifier: %v: %w", tp, err, requirements.ErrUnknown)
	}
	for _, l := range ve.Log {
		if strings.Contains(l, "invalid mem access") {
			return strings.TrimSpace(l), nil
		}
	}
	return strings.TrimSpace(strings.Join(ve.Log, " | ")), nil
}
