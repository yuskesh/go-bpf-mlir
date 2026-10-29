package requirements

import (
	"encoding/json"
	"errors"
)

// QueryKfuncLoad is the privilege-dependent exact-profile kfunc load query.
const QueryKfuncLoad = "kfunc_loads"

// KfuncProfile is the initial profile derived from actual ELF, with no mutable
// containers. It does not certify compiler provenance or later ProgramSpec
// overrides made by the caller.
type KfuncProfile struct {
	Kind, Section, ProgType string
	ProgTypeID              int64
	ProgFlags               uint32
	AttachType              string
	TargetKind, Target      string
	ContextIdentity         string
	Recipe                  string
}

// KernelKfuncLoadCaps checks permission by loading a finite recipe. False
// requires a complete rejection naming the callee. Missing recipes, dependencies
// or environment yield ErrUnknown; general I/O failures remain errors.
type KernelKfuncLoadCaps interface {
	HasKfuncLoad(profile KfuncProfile, name, ret string, args []string) (bool, error)
}

// KfuncLoadKey is an ordered JSON array separating profile and prototype.
// Symbol is diagnostic attribution only; raw BTF IDs are not persistent keys.
func KfuncLoadKey(p KfuncProfile, name, ret string, args []string) string {
	a := append([]string{}, args...)
	b, _ := json.Marshal([]any{p.Recipe, name, ret, a, p.ProgType, p.ProgTypeID, p.Kind, p.Section, p.ProgFlags, p.AttachType, p.TargetKind, p.Target, p.ContextIdentity})
	return string(b)
}

func checkKfuncLoad(req *Requirements, k Kfunc, caps Capabilities) ([]Unmet, error) {
	unknown := func(detail string) ([]Unmet, error) {
		u := Unmet{Kind: "kfunc_allowed_unknown", Program: k.Program, Name: k.Name, Detail: detail}
		return []Unmet{u}, nil
	}
	p, err := kfuncProfileFor(req, k.Program)
	if err != nil {
		return unknown(err.Error())
	}
	c, ok := capsAs[KernelKfuncLoadCaps](caps, QueryKfuncLoad)
	if !ok {
		return unknown("no kfunc load permission probe")
	}
	allowed, err := c.HasKfuncLoad(p, k.Name, k.Ret, append([]string{}, k.Args...))
	if errors.Is(err, ErrUnknown) {
		return unknown(err.Error())
	}
	if err != nil {
		return nil, err
	}
	if !allowed {
		u := Unmet{Kind: "kfunc_allowed", Program: k.Program, Name: k.Name, Detail: "kernel rejected this kfunc in the exact initial profile " + KfuncLoadKey(p, k.Name, k.Ret, k.Args)}
		return []Unmet{u}, nil
	}
	return nil, nil
}
