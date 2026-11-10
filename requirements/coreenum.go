package requirements

import (
	"errors"
)

// Format 26 adds coreenum <program> <enum> <name>: the program reads
// a kernel enum constant through a CO-RE enum value relocation (ebpf.scx.const
// and ebpf.core.enum_value — `ld_imm64` with .BTF.ext kind 11). The loader
// writes the target's value, so the row carries no value: Check only confirms
// that the target BTF has the constant (an absent one is poisoned by the
// loader). See docs/requirements_format.md sections 3, 5 and 6.
const CoreEnumMinVersion = 26

// CoreEnum is coreenum <program> <enum> <name>.
type CoreEnum struct {
	Program, Enum, Name string
}

// parseCoreEnum parses a coreenum row. Rows sort by program row order, then
// enum, then name. The same program's (enum, name) cannot also be an enumval
// row (value): one constant is either an immediate or a relocation.
func (r *Requirements) parseCoreEnum(n int, f []string, line string, byName map[string]int) error {
	pi, ok := byName[f[1]]
	if !ok {
		return perr(n, f[0], RuleOrder, "%s line %d: coreenum for unknown program %q", Section, n, f[1])
	}
	if !validCName(f[2]) || !validCName(f[3]) {
		return perr(n, f[0], RuleValue, "%s line %d: bad coreenum row %q", Section, n, line)
	}
	if l := len(r.CoreEnums); l > 0 {
		p := r.CoreEnums[l-1]
		pp := byName[p.Program]
		if pi < pp || (pi == pp && (f[2] < p.Enum || (f[2] == p.Enum && f[3] <= p.Name))) {
			return perr(n, f[0], RuleOrder, "%s line %d: coreenum row out of order or repeated %q", Section, n, line)
		}
	}
	for _, e := range r.EnumVals {
		if e.Program == f[1] && e.Enum == f[2] && e.Name == f[3] {
			return perr(n, f[0], RuleValue, "%s line %d: coreenum %s %s %s is also an enumval row (an immediate and a relocation of the same constant)", Section, n, f[1], f[2], f[3])
		}
	}
	r.CoreEnums = append(r.CoreEnums, CoreEnum{Program: f[1], Enum: f[2], Name: f[3]})
	return nil
}

// checkCoreEnums checks coreenum rows through enum_values (the value is
// ignored). An absent constant is coreenum; no query or an unknown answer is
// coreenum_unknown. Both block: an absent constant is a poisoned instruction
// the verifier rejects only when it is reachable, so a load could silently
// succeed without it. Keep Unmet Kind as literals for spec_test's
// source/table comparison.
func checkCoreEnums(req *Requirements, caps Capabilities) ([]Unmet, error) {
	var out []Unmet
	ec, ok := capsAs[KernelEnumValues](caps, QueryEnumValues)
	for _, e := range req.CoreEnums {
		name := e.Enum + "." + e.Name
		if !ok {
			out = append(out, Unmet{Kind: "coreenum_unknown", Program: e.Program, Name: name, Detail: "no enum value probe"})
			continue
		}
		_, err := ec.EnumValue(e.Enum, e.Name)
		switch {
		case errors.Is(err, ErrUnknown):
			out = append(out, Unmet{Kind: "coreenum_unknown", Program: e.Program, Name: name, Detail: err.Error()})
		case errors.Is(err, ErrEnumAbsent):
			out = append(out, Unmet{Kind: "coreenum", Program: e.Program, Name: name, Detail: err.Error()})
		case err != nil:
			return nil, err
		}
	}
	return out, nil
}
