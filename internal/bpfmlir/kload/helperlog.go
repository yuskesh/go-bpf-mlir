//go:build linux

package kload

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/yuskesh/go-bpf-mlir/requirements"
)

// helperRefusals are the verifier's texts for a helper the program type cannot call: cilium's three
// (features/prog.go). A line counts only if it also names the probed helper's exact #<id>.
var helperRefusals = []string{"invalid func", "program of this type cannot use helper", "unknown func"}

// helperLogOpts are the classifier's knobs. The zero value is the real behaviour; the tests set the
// fields to make the mutants.
type helperLogOpts struct {
	anyHelper     bool // a refusal text alone is enough (the probed #<id> is not required)
	window        int  // search only the last window lines (0: every line)
	rescueUnknown bool // the whole-log rescue answers Unknown instead of false
}

// helperAnswer maps cilium's helper probe result to HasHelper's answer. cilium answers ErrNotSupported
// only when the refusal is in the last five verifier log lines; a kernel that prints an explanation block
// after it (7.3.1) leaves an EINVAL VerifierError instead. That error carries the whole log, so the
// probe is classified again over every line. Only an EINVAL whose log has a line with a refusal text
// and the probed helper's exact #<id> becomes false (a blocking helper Unmet). Every other error is
// returned as it is: a checking error, never Unknown (helper_unknown does not block).
func helperAnswer(err error, helperID int64) (bool, error) {
	return helperAnswerOpts(err, helperID, helperLogOpts{})
}

func helperAnswerOpts(err error, helperID int64, o helperLogOpts) (bool, error) {
	if err == nil {
		return true, nil
	}
	if errors.Is(err, ebpf.ErrNotSupported) {
		return false, nil
	}
	var verr *ebpf.VerifierError
	if !errors.As(err, &verr) || !errors.Is(err, unix.EINVAL) {
		return false, err
	}
	log := verr.Log
	if o.window > 0 && len(log) > o.window {
		log = log[len(log)-o.window:]
	}
	for _, l := range log {
		if !lineRefusesHelper(l, helperID, o.anyHelper) {
			continue
		}
		if o.rescueUnknown {
			return false, fmt.Errorf("helper probe log names helper #%d: %w", helperID, requirements.ErrUnknown)
		}
		return false, nil
	}
	return false, err
}

// lineRefusesHelper: the line holds a refusal text and the exact #<id> (followed by a non-digit or the
// end of the line, so #13 does not match #136).
func lineRefusesHelper(l string, helperID int64, anyHelper bool) bool {
	refused := false
	for _, r := range helperRefusals {
		if strings.Contains(l, r) {
			refused = true
			break
		}
	}
	if !refused {
		return false
	}
	if anyHelper {
		return true
	}
	tag := fmt.Sprintf("#%d", helperID)
	for i := 0; ; {
		j := strings.Index(l[i:], tag)
		if j < 0 {
			return false
		}
		end := i + j + len(tag)
		if end == len(l) || l[end] < '0' || l[end] > '9' {
			return true
		}
		i = end
	}
}
