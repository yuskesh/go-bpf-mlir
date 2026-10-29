package kload

// Probe Tracing helper support per expected_attach_type; cilium v0.22's
// HaveProgramHelper does not implement Tracing. Match cilium's probe rules:
// accept or EACCES after prototype checking means present; EINVAL with
// invalid-func/type-cannot-use-helper/unknown-func means absent; other outcomes
// are Unknown. Also treat the named ENOTSUPP supported-only-for-fentry/fexit/
// fmod_ret diagnostic as absent for this attach type, even if its proto exists.

import (
	"errors"
	"fmt"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// TracingHelperFentryTarget is the kernel test function used for fentry/fexit probes.
const TracingHelperFentryTarget = "bpf_fentry_test1"

// TracingHelperRawTPTarget is the tp_btf probe tracepoint, also used by nullable probes.
const TracingHelperRawTPTarget = "sched_process_fork"

// Fixed probe targets for trace_iter and modify_return.
const (
	TracingHelperIterTarget    = "bpf_map_elem"
	TracingHelperFmodRetTarget = "bpf_modify_return_test"
)

var (
	tracingHelperMu   sync.Mutex
	tracingHelperMemo = map[string]tracingHelperAnswer{}
)

type tracingHelperAnswer struct {
	have bool
	err  error
}

// HasTracingHelper checks helper availability for a Tracing attach type.
func (LiveCaps) HasTracingHelper(attachType, helper string, helperID int64) (bool, error) {
	key := fmt.Sprintf("%s/%d", attachType, helperID)
	tracingHelperMu.Lock()
	defer tracingHelperMu.Unlock()
	if a, ok := tracingHelperMemo[key]; ok {
		return a.have, a.err
	}
	have, err := probeTracingHelper(attachType, helper, helperID)
	tracingHelperMemo[key] = tracingHelperAnswer{have, err}
	return have, err
}

func probeTracingHelper(attachType, helper string, helperID int64) (bool, error) {
	spec := &ebpf.ProgramSpec{
		Name: "helper_probe", Type: ebpf.Tracing, License: "GPL",
		Instructions: asm.Instructions{
			asm.BuiltinFunc(helperID).Call(),
			asm.LoadImm(asm.R0, 0, asm.DWord),
			asm.Return(),
		},
	}
	switch attachType {
	case "trace_fentry":
		spec.AttachType, spec.AttachTo = ebpf.AttachTraceFEntry, TracingHelperFentryTarget
	case "trace_fexit":
		spec.AttachType, spec.AttachTo = ebpf.AttachTraceFExit, TracingHelperFentryTarget
	case "trace_raw_tp":
		spec.AttachType, spec.AttachTo = ebpf.AttachTraceRawTp, TracingHelperRawTPTarget
	case "trace_iter": // Iterator target bpf_map_elem.
		spec.AttachType, spec.AttachTo = ebpf.AttachTraceIter, TracingHelperIterTarget
	case "modify_return": // fmod_ret, including typed trace_fmod_ret and generic modify_return.
		spec.AttachType, spec.AttachTo = ebpf.AttachModifyReturn, TracingHelperFmodRetTarget
	default:
		return false, fmt.Errorf("no Tracing helper probe for attach type %q: %w", attachType, requirements.ErrUnknown)
	}
	prog, err := ebpf.NewProgramWithOptions(spec, ebpf.ProgramOptions{LogLevel: ebpf.LogLevelBranch})
	if err == nil {
		prog.Close()
		return true, nil
	}
	var verr *ebpf.VerifierError
	if !errors.As(err, &verr) {
		// Permission/target failures did not reach the verifier: Unknown.
		return false, fmt.Errorf("Tracing helper probe (%s, %s): %v: %w", attachType, helper, err, requirements.ErrUnknown)
	}
	tag := fmt.Sprintf("#%d", helperID)
	switch {
	case errors.Is(err, unix.EACCES):
		return true, nil
	case errors.Is(err, unix.EINVAL):
		if logContainsAll(verr.Log, "invalid func", tag) || logContainsAll(verr.Log, "program of this type cannot use helper", tag) || logContainsAll(verr.Log, "unknown func") {
			return false, nil
		}
	}
	if logContainsAll(verr.Log, tag, "supported only for") {
		return false, nil
	}
	// For Unknown, retain the helper line, otherwise the last pre-statistics line.
	last := ""
	for _, l := range verr.Log {
		if strings.Contains(l, tag) {
			last = l
		}
	}
	if last == "" {
		for _, l := range verr.Log {
			if !strings.HasPrefix(l, "processed ") {
				last = l
			}
		}
	}
	return false, fmt.Errorf("Tracing helper probe (%s, %s): the verifier rejected it for another reason (%q): %w", attachType, helper, last, requirements.ErrUnknown)
}

// logContainsAll matches a line containing every word, as cilium features does.
func logContainsAll(log []string, needles ...string) bool {
	for _, l := range log {
		ok := true
		for _, n := range needles {
			if !strings.Contains(l, n) {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}
