package requirements

import (
	"errors"
	"fmt"
)

// checkFentryArgs retains the structural/count query even for scalar-only and
// skip-only prefixes. Scalar element queries use the existing one-based key.
func checkFentryArgs(a Attach, caps Capabilities) ([]Unmet, error) {
	args := append([]string(nil), a.FArgs...)
	for i, typ := range args {
		if validIntSpelling(typ) {
			args[i] = "-"
		}
	}
	var out []Unmet
	fa, ok := capsAs[KernelFuncArgs](caps, QueryFuncArgs)
	if !ok {
		out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: a.Target})
	} else {
		diffs, err := fa.CheckFuncArgs(a.Target, args)
		if err != nil {
			if !errors.Is(err, ErrUnknown) {
				return nil, err
			}
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()})
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "farg", Program: a.Program, Name: a.Target, Detail: fmt.Sprintf("program %s: %s", a.Program, d)})
		}
	}
	for i, typ := range a.FArgs {
		if !validIntSpelling(typ) {
			continue
		}
		name := fmt.Sprintf("%d of %s (%s)", i+1, a.Target, typ)
		fp, ok := capsAs[KernelFuncParams](caps, QueryFuncParam)
		if !ok {
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: name, Detail: "no BTF probe"})
			continue
		}
		diffs, err := fp.CheckFuncParam(a.Target, i+1, typ)
		if err != nil {
			if !errors.Is(err, ErrUnknown) {
				return nil, err
			}
			out = append(out, Unmet{Kind: "farg_unknown", Program: a.Program, Name: name, Detail: err.Error()})
		}
		for _, d := range diffs {
			out = append(out, Unmet{Kind: "farg", Program: a.Program, Name: name, Detail: fmt.Sprintf("program %s: %s", a.Program, d)})
		}
	}
	return out, nil
}
