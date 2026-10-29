package requirements

import (
	"errors"
	"fmt"
)

// TracepointBufferCaps checks the BTF pointee of raw tracepoint args[0].
// It does not query writable_size or attach success.
type TracepointBufferCaps interface {
	CheckTracepointBuffer(name, pointee string) ([]string, error)
}

const QueryTracepointBuffer = "tracepoint_buffer"

// TracepointBufferKey encodes the unprefixed target and fixed argument zero.
func TracepointBufferKey(name, pointee string) string { return name + "/0/" + pointee }

func (r *Requirements) parseTPBuffer(n int, f []string, line string, afterAttach bool, byName map[string]int) error {
	k := len(r.Attaches) - 1
	idx, declared := byName[f[1]]
	if !afterAttach || !declared || k < 0 || r.Attaches[k].Program != f[1] ||
		!r.Attaches[k].Generic || r.Attaches[k].AttachType != "raw_tp_writable" || r.Attaches[k].TPBufferType != "" {
		return perr(n, f[0], RuleOrder, "%s line %d: tpbuf row out of order %q", Section, n, line)
	}
	a := &r.Attaches[k]
	p := r.Programs[idx]
	// UAPI raw_tracepoint_writable is 24; a dedicated test checks abi/uapi.tsv.
	if f[2] != "i32" || p.ProgType != "raw_tracepoint_writable" || p.ProgTypeID != 24 ||
		a.TargetKind != "rawtp" || !validCName(a.TargetValue) {
		return perr(n, f[0], RuleValue, "%s line %d: bad tpbuf row %q (needs raw_tracepoint_writable/24, rawtp:<IDENT>, i32)", Section, n, line)
	}
	a.TPBufferType = f[2]
	return nil
}

func checkTPBuffer(a Attach, caps Capabilities) ([]Unmet, error) {
	if a.TPBufferType == "" {
		return nil, nil
	}
	detail := fmt.Sprintf("tpbuf tracepoint %s: argument 0 expected pointee %s", a.TargetValue, a.TPBufferType)
	unknown := func(why string) []Unmet {
		return []Unmet{{Kind: "attach_unknown", Program: a.Program, Name: a.TargetValue, Detail: detail + "; " + why}}
	}
	tc, ok := capsAs[TracepointBufferCaps](caps, QueryTracepointBuffer)
	if !ok {
		return unknown("no tracepoint_buffer query"), nil
	}
	diffs, err := tc.CheckTracepointBuffer(a.TargetValue, a.TPBufferType)
	switch {
	case errors.Is(err, ErrUnknown):
		return unknown(err.Error()), nil
	case err != nil:
		return nil, err
	}
	var out []Unmet
	for _, diff := range diffs {
		out = append(out, Unmet{Kind: "attach", Program: a.Program, Name: a.TargetValue, Detail: detail + "; " + diff})
	}
	return out, nil
}
