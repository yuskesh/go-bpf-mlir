package requirements

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Format 20 adds enumval <program> <enum> <name> <value>: a kernel enum
// constant the compiler took from its UAPI table (ebpf.scx.const). The loader
// compares the value with the target BTF before load; see
// docs/requirements_format.md sections 3, 5 and 6.
const EnumValMinVersion = 20

// EnumVal is enumval <program> <enum> <name> <value>; Value is the 64-bit
// pattern (0x and exactly 16 lowercase hexadecimal digits in the row).
type EnumVal struct {
	Program, Enum, Name string
	Value               uint64
}

// ErrEnumAbsent marks an enum or constant missing from the target BTF. It is
// a known answer (Unmet enumval), not ErrUnknown.
var ErrEnumAbsent = errors.New("enum constant absent")

// KernelEnumValues answers enum_values: the 64-bit pattern of enum constant
// name in the target BTF ENUM / ENUM64 named enum. Absence wraps
// ErrEnumAbsent; unreadable BTF wraps ErrUnknown.
type KernelEnumValues interface {
	EnumValue(enum, name string) (uint64, error)
}

// EnumValueKey encodes <enum>/<name> for recorded enum_values (section 10).
func EnumValueKey(enum, name string) string { return enum + "/" + name }

// FormatEnumValue spells a value as in enumval rows and recorded answers.
func FormatEnumValue(v uint64) string { return fmt.Sprintf("0x%016x", v) }

// parseEnumValue reads 0x followed by exactly 16 lowercase hexadecimal digits.
func parseEnumValue(s string) (uint64, bool) {
	h, ok := strings.CutPrefix(s, "0x")
	if !ok || len(h) != 16 || strings.ToLower(h) != h {
		return 0, false
	}
	v, err := strconv.ParseUint(h, 16, 64)
	return v, err == nil
}

// parseEnumVal parses an enumval row. Rows sort by program row order, then
// enum, then name; the same (enum, name) has one value in an object.
func (r *Requirements) parseEnumVal(n int, f []string, line string, byName map[string]int) error {
	pi, ok := byName[f[1]]
	if !ok {
		return perr(n, f[0], RuleOrder, "%s line %d: enumval for unknown program %q", Section, n, f[1])
	}
	v, okv := parseEnumValue(f[4])
	if !validCName(f[2]) || !validCName(f[3]) || !okv {
		return perr(n, f[0], RuleValue, "%s line %d: bad enumval row %q", Section, n, line)
	}
	if l := len(r.EnumVals); l > 0 {
		p := r.EnumVals[l-1]
		pp := byName[p.Program]
		if pi < pp || (pi == pp && (f[2] < p.Enum || (f[2] == p.Enum && f[3] <= p.Name))) {
			return perr(n, f[0], RuleOrder, "%s line %d: enumval row out of order or repeated %q", Section, n, line)
		}
	}
	for _, e := range r.EnumVals {
		if e.Enum == f[2] && e.Name == f[3] && e.Value != v {
			return perr(n, f[0], RuleValue, "%s line %d: enumval %s %s has value %s, but an earlier row has %s", Section, n, f[2], f[3], f[4], FormatEnumValue(e.Value))
		}
	}
	for _, c := range r.CoreEnums { // either order of the two rows.
		if c.Program == f[1] && c.Enum == f[2] && c.Name == f[3] {
			return perr(n, f[0], RuleValue, "%s line %d: enumval %s %s %s is also a coreenum row (an immediate and a relocation of the same constant)", Section, n, f[1], f[2], f[3])
		}
	}
	r.EnumVals = append(r.EnumVals, EnumVal{Program: f[1], Enum: f[2], Name: f[3], Value: v})
	return nil
}

// checkEnumVals checks enumval rows. A different value or an absent constant
// is enumval; no query or an unknown answer is enumval_unknown. Both block:
// a different value silently changes what the program does. Keep Unmet Kind
// as literals for spec_test's source/table comparison.
func checkEnumVals(req *Requirements, caps Capabilities) ([]Unmet, error) {
	var out []Unmet
	ec, ok := capsAs[KernelEnumValues](caps, QueryEnumValues)
	for _, e := range req.EnumVals {
		name := e.Enum + "." + e.Name
		if !ok {
			out = append(out, Unmet{Kind: "enumval_unknown", Program: e.Program, Name: name, Detail: "no enum value probe"})
			continue
		}
		got, err := ec.EnumValue(e.Enum, e.Name)
		switch {
		case errors.Is(err, ErrUnknown):
			out = append(out, Unmet{Kind: "enumval_unknown", Program: e.Program, Name: name, Detail: err.Error()})
		case errors.Is(err, ErrEnumAbsent):
			out = append(out, Unmet{Kind: "enumval", Program: e.Program, Name: name,
				Detail: fmt.Sprintf("%v (the object was compiled with %s)", err, FormatEnumValue(e.Value))})
		case err != nil:
			return nil, err
		case got != e.Value:
			out = append(out, Unmet{Kind: "enumval", Program: e.Program, Name: name,
				Detail: fmt.Sprintf("the target's %s is %s, the object was compiled with %s", name, FormatEnumValue(got), FormatEnumValue(e.Value))})
		}
	}
	return out, nil
}

// EnumValue key: <enum>/<name>. A text answer is the value; a diffs answer
// records absence (its text).
func (c *RecordedCaps) EnumValue(enum, name string) (uint64, error) {
	a, err := c.answer(QueryEnumValues, EnumValueKey(enum, name))
	if err != nil {
		return 0, err
	}
	if a.Diffs != nil {
		return 0, fmt.Errorf("%s: %w", strings.Join(*a.Diffs, "; "), ErrEnumAbsent)
	}
	if a.Text == nil {
		return 0, fmt.Errorf("recorded caps: %s %q is not a text or diffs answer", QueryEnumValues, EnumValueKey(enum, name))
	}
	v, ok := parseEnumValue(*a.Text)
	if !ok {
		return 0, fmt.Errorf("recorded caps: %s %q: value %q is not 0x and 16 lowercase hexadecimal digits", QueryEnumValues, EnumValueKey(enum, name), *a.Text)
	}
	return v, nil
}

// EnumValue forwards an available query (capsAs checks HasQuery first) and
// records the value as text, absence as diffs, Unknown and errors as such.
func (r *Recorder) EnumValue(enum, name string) (uint64, error) {
	v, err := r.under.(KernelEnumValues).EnumValue(enum, name)
	key := EnumValueKey(enum, name)
	switch {
	case errors.Is(err, ErrUnknown):
		r.put(QueryEnumValues, key, Answer{Unknown: err.Error()})
	case errors.Is(err, ErrEnumAbsent):
		// The sentinel suffix is added back on read, so a round trip keeps the text.
		d := []string{strings.TrimSuffix(err.Error(), ": "+ErrEnumAbsent.Error())}
		r.put(QueryEnumValues, key, Answer{Diffs: &d})
	case err != nil:
		r.put(QueryEnumValues, key, Answer{Error: err.Error()})
	default:
		s := FormatEnumValue(v)
		r.put(QueryEnumValues, key, Answer{Text: &s})
	}
	return v, err
}
