// Package bindrt implements the load contracts shared by generated bindings and frontends.
// It depends only on the standard library, requirements and layout; cilium glue
// (ELF parsing, LoadAndAssign and prog_array updates) stays in the caller.
// Recorded caps describe probed_as privileges, not necessarily load privileges.
// These checks do not probe or split answers by privilege automatically. When
// privileges differ, callers must pass RecordedCaps.ForLoad with live caps from
// the loading process to re-probe privilege-dependent queries. See docs/nonroot.md.
package bindrt

import "github.com/yuskesh/go-bpf-mlir/requirements"

// TargetError reports blocking requirements before loading the embedded object.
// Capability probes may create and close temporary kernel objects. Generated
// packages alias this type, so callers can handle it across binding packages.
type TargetError struct{ Unmet []requirements.Unmet }

func (e *TargetError) Error() string {
	msg := "the target does not satisfy this object's requirements (not loaded):"
	for _, u := range e.Unmet {
		msg += "\n  " + u.String()
	}
	return msg
}

// PrecheckError reports a failed precheck, such as unreadable requirements, nil
// capabilities or a failed probe, before loading the embedded program. Probes
// may create kernel objects. Unwrap exposes the cause; test for PrecheckError
// before VerifierError, which a probe failure may wrap. Generated bindings alias it.
type PrecheckError struct{ Err error }

func (e *PrecheckError) Error() string {
	return "target precheck failed before loading the embedded program: " + e.Err.Error()
}

func (e *PrecheckError) Unwrap() error { return e.Err }
