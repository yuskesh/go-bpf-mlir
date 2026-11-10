package requirements

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// typed ksym VARs, CONFIG_*
// externs and existence guards (docs/requirements_format.md sections 3, 5, 6,
// 8 and 10).
//
//	ksymvar <name> percpu <slot> <weak|strong> [guarded <g> …]
//	kconfig <name> <bool|tristate|char|i16|u16|i32|u32|i64|u64> <weak|strong>
//	guard <g> <ksym|type|field> <target>
//
// and a trailing "guarded <g> …" on kfield rows. A guarded row is excused only
// when one of its guards is confirmed false (the guarded branch never runs);
// true is checked like an unguarded row, and Unknown or an error is never
// false. A strong ksymvar is never excused (the reader refuses its guarded
// suffix), and a weak one always carries its own ksym guard.

// KsymVarMinVersion is the first format with ksymvar / kconfig / guard rows
// and the guarded suffix.
const KsymVarMinVersion = 24

// KsymVar is ksymvar <name> percpu <slot> <weak|strong> [guarded <g> …].
type KsymVar struct {
	Name, Class, Slot, Bind string // Class is percpu; Slot is i8…u64 or ptr:<S>.
	Guards                  []int
}

// Kconfig is kconfig <name> <type> <weak|strong>.
type Kconfig struct {
	Name, Type, Bind string
}

// Guard is guard <g> <ksym|type|field> <target>.
type Guard struct {
	N            int
	Kind, Target string
}

// Bindings and guard kinds.
const (
	BindWeak    = "weak"
	BindStrong  = "strong"
	GuardKsym   = "ksym"
	GuardType   = "type"
	GuardField  = "field"
	KsymPercpu  = "percpu"
	kconfigPfx  = "CONFIG_"
	guardedWord = "guarded"
)

// kconfigTypes is the kconfig row's value-type domain (libbpf's KCFG_BOOL,
// KCFG_TRISTATE, KCFG_CHAR and KCFG_INT; a one-byte integer is KCFG_CHAR).
var kconfigTypes = map[string]bool{"bool": true, "tristate": true, "char": true,
	"i16": true, "i32": true, "i64": true, "u16": true, "u32": true, "u64": true} // No i8 / u8: a one-byte INT is KCFG_CHAR (find_kcfg_type), spelled char.

// ErrKsymAbsent marks a VAR confirmed absent from vmlinux and every module
// BTF (a known answer, not ErrUnknown).
var ErrKsymAbsent = errors.New("ksym VAR absent")

// ErrKconfigAbsent marks a CONFIG_* without a CONFIG_<name>= line in a
// readable kconfig file ("# CONFIG_X is not set" included).
var ErrKconfigAbsent = errors.New("kconfig option not set")

// KernelKsymVars answers ksym_vars: "percpu <slot>" for a VAR in the per-CPU
// DATASEC (.data..percpu) whose type is spelled as in ksymvar rows,
// "percpu other:<what>" for a per-CPU VAR of another type and "plain <…>" for a
// VAR outside the per-CPU DATASEC. Confirmed absence wraps ErrKsymAbsent; an
// unknown module set, a VAR only in a module, duplicate VARs or unreadable BTF
// wrap ErrUnknown.
type KernelKsymVars interface {
	KsymVar(name string) (string, error)
}

// KernelKconfig answers kconfig: the raw text after '=' of the first
// CONFIG_<name>= line of the kconfig file (/boot/config-<release>, then
// /proc/config.gz). Absence wraps ErrKconfigAbsent; a missing, unreadable or
// malformed file wraps ErrUnknown.
type KernelKconfig interface {
	KconfigValue(name string) (string, error)
}

// BTFPresence answers btf_presence: whether STRUCT s (or its field path) is in
// vmlinux. false means confirmed absent from vmlinux and every module BTF;
// anything else (only in a module, an unknown module set, duplicates) wraps
// ErrUnknown.
type BTFPresence interface {
	TypePresent(s string) (bool, error)
	FieldPresent(s, path string) (bool, error)
}

// BTFPresenceKey encodes type/<S> or field/<S>.<path> (section 10).
func BTFPresenceKey(kind, target string) string { return kind + "/" + target }

// validKsymSlot is i8…u64 or ptr:<C identifier>.
func validKsymSlot(s string) bool {
	if validIntSpelling(s) {
		return true
	}
	t, ok := strings.CutPrefix(s, "ptr:")
	return ok && validCName(t)
}

// validKconfigName is CONFIG_ followed by one or more [A-Za-z0-9_].
func validKconfigName(s string) bool {
	rest, ok := strings.CutPrefix(s, kconfigPfx)
	if !ok || rest == "" {
		return false
	}
	for _, c := range rest {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// validGuardNumber is a canonical non-negative decimal.
func validGuardNumber(s string) (int, bool) {
	if s == "" || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.Atoi(s)
	return v, err == nil
}

// parseGuardedList reads the numbers after "guarded" (strictly increasing).
func parseGuardedList(n int, row string, list []string, line string) ([]int, error) {
	if len(list) == 0 {
		return nil, perr(n, row, RuleFields, "%s line %d: guarded needs one or more guard numbers, got %q", Section, n, line)
	}
	var out []int
	for _, s := range list {
		g, ok := validGuardNumber(s)
		if !ok {
			return nil, perr(n, row, RuleValue, "%s line %d: bad guard number %q in %q", Section, n, s, line)
		}
		if l := len(out); l > 0 && g <= out[l-1] {
			return nil, perr(n, row, RuleGuardOrder, "%s line %d: guarded numbers must be strictly increasing, got %d after %d", Section, n, g, out[l-1])
		}
		out = append(out, g)
	}
	return out, nil
}

// externOrder enforces ksymvar → kconfig → guard among the three kinds.
func (r *Requirements) externOrder(n int, kind string) error {
	late := ""
	switch kind {
	case "ksymvar":
		if len(r.Kconfigs) > 0 {
			late = "kconfig"
		}
		if len(r.Guards) > 0 {
			late = "guard"
		}
	case "kconfig":
		if len(r.Guards) > 0 {
			late = "guard"
		}
	}
	if late != "" {
		return perr(n, kind, RuleOrder, "%s line %d: %s rows come before %s rows", Section, n, kind, late)
	}
	return nil
}

// parseKsymVar reads a ksymvar row and its optional guarded list.
func (r *Requirements) parseKsymVar(n int, f []string, guarded []string, hasGuarded bool, line string) error {
	if err := r.externOrder(n, f[0]); err != nil {
		return err
	}
	if !validCName(f[1]) || f[2] != KsymPercpu || !validKsymSlot(f[3]) || (f[4] != BindWeak && f[4] != BindStrong) {
		return perr(n, f[0], RuleValue, "%s line %d: bad ksymvar row %q (want ksymvar <name> percpu <i8…u64|ptr:<struct>> <weak|strong>)", Section, n, line)
	}
	if k := len(r.KsymVars); k > 0 && r.KsymVars[k-1].Name >= f[1] {
		return perr(n, f[0], RuleOrder, "%s line %d: ksymvar rows must be in strictly increasing name order, got %q after %q", Section, n, f[1], r.KsymVars[k-1].Name)
	}
	v := KsymVar{Name: f[1], Class: f[2], Slot: f[3], Bind: f[4]}
	if hasGuarded {
		gs, err := parseGuardedList(n, f[0], guarded, line)
		if err != nil {
			return err
		}
		if v.Bind == BindStrong {
			return perr(n, f[0], RuleGuardStrong, "%s line %d: strong ksymvar %s is guarded — a strong extern must resolve whatever its guards say", Section, n, v.Name)
		}
		v.Guards = gs
	} else if v.Bind == BindWeak {
		return perr(n, f[0], RuleGuardMissing, "%s line %d: weak ksymvar %s has no guarded list — the compiler reads a weak VAR only under its own ksym guard", Section, n, v.Name)
	}
	r.KsymVars = append(r.KsymVars, v)
	r.guardedLines = append(r.guardedLines, guardedRow{line: n, ksym: len(r.KsymVars) - 1, kfield: -1})
	return nil
}

// parseKconfig reads a kconfig row.
func (r *Requirements) parseKconfig(n int, f []string, line string) error {
	if err := r.externOrder(n, f[0]); err != nil {
		return err
	}
	if !validKconfigName(f[1]) || !kconfigTypes[f[2]] || (f[3] != BindWeak && f[3] != BindStrong) {
		return perr(n, f[0], RuleValue, "%s line %d: bad kconfig row %q (want kconfig CONFIG_<name> <bool|tristate|char|i16|u16|i32|u32|i64|u64> <weak|strong>)", Section, n, line)
	}
	if k := len(r.Kconfigs); k > 0 && r.Kconfigs[k-1].Name >= f[1] {
		return perr(n, f[0], RuleOrder, "%s line %d: kconfig rows must be in strictly increasing name order, got %q after %q", Section, n, f[1], r.Kconfigs[k-1].Name)
	}
	r.Kconfigs = append(r.Kconfigs, Kconfig{Name: f[1], Type: f[2], Bind: f[3]})
	return nil
}

// validGuardTarget checks the target spelling of a guard kind.
func validGuardTarget(kind, target string) bool {
	switch kind {
	case GuardKsym, GuardType:
		return validCName(target)
	case GuardField:
		s, path, ok := strings.Cut(target, ".")
		return ok && validCName(s) && validKFieldPath(path)
	}
	return false
}

// parseGuard reads a guard row: numbered 0, 1, … in row order and strictly
// increasing by (kind, target) in byte order.
func (r *Requirements) parseGuard(n int, f []string, line string) error {
	g, ok := validGuardNumber(f[1])
	if !ok {
		return perr(n, f[0], RuleValue, "%s line %d: bad guard number %q", Section, n, f[1])
	}
	if g != len(r.Guards) {
		return perr(n, f[0], RuleGuardOrder, "%s line %d: guard rows are numbered 0, 1, … in row order — want %d, got %d", Section, n, len(r.Guards), g)
	}
	if !validGuardTarget(f[2], f[3]) {
		return perr(n, f[0], RuleValue, "%s line %d: bad guard row %q (want guard <g> ksym <name> | type <struct> | field <struct>.<path>)", Section, n, line)
	}
	if k := len(r.Guards); k > 0 {
		p := r.Guards[k-1]
		if p.Kind > f[2] || (p.Kind == f[2] && p.Target >= f[3]) {
			return perr(n, f[0], RuleGuardOrder, "%s line %d: guard rows must be strictly increasing by (kind, target), got %s %s after %s %s", Section, n, f[2], f[3], p.Kind, p.Target)
		}
	}
	r.Guards = append(r.Guards, Guard{N: g, Kind: f[2], Target: f[3]})
	return nil
}

// guardedRow records a row that can carry a guarded list, in document order.
type guardedRow struct {
	line         int
	ksym, kfield int // Index into KsymVars or KFields (-1 when the other).
}

// checkGuardBindings runs the end-of-document binding rules (line 0):
// guard_orphan, guard_target, then guard_unused.
func (r *Requirements) checkGuardBindings() error {
	used := make([]bool, len(r.Guards))
	for _, gr := range r.guardedLines {
		var gs []int
		row, what := "", ""
		var kf KField
		if gr.ksym >= 0 {
			v := r.KsymVars[gr.ksym]
			gs, row, what = v.Guards, "ksymvar", "ksymvar "+v.Name
		} else {
			kf = r.KFields[gr.kfield]
			gs, row, what = r.KFieldGuards[gr.kfield], "kfield", "kfield "+kf.Program+" "+kf.Struct+"."+kf.Field
		}
		for _, g := range gs {
			if g >= len(r.Guards) {
				return perr(0, row, RuleGuardOrphan, "%s: %s (line %d) is guarded by %d, which has no guard row", Section, what, gr.line, g)
			}
			gd := r.Guards[g]
			ok := false
			if gr.ksym >= 0 {
				ok = gd.Kind == GuardKsym && gd.Target == r.KsymVars[gr.ksym].Name
			} else {
				switch gd.Kind {
				case GuardField:
					ok = gd.Target == kf.Struct+"."+kf.Field
				case GuardType:
					ok = gd.Target == kf.Struct
				}
			}
			if !ok {
				return perr(0, row, RuleGuardTarget, "%s: %s (line %d) is guarded by %d (%s %s), which guards another target", Section, what, gr.line, g, gd.Kind, gd.Target)
			}
			used[g] = true
		}
	}
	for g, u := range used {
		if !u {
			return perr(0, "guard", RuleGuardUnused, "%s: guard %d (%s %s) marks no row", Section, g, r.Guards[g].Kind, r.Guards[g].Target)
		}
	}
	return nil
}

// Guard states.
const (
	guardFalse = iota
	guardTrue
	guardUnknown
)

// guardState asks the guard's query: false is confirmed absence, unknown a
// missing query or an Unknown answer; other errors are returned (never false).
func guardState(g Guard, caps Capabilities) (int, string, error) {
	switch g.Kind {
	case GuardKsym:
		kq, ok := capsAs[KernelKsymVars](caps, QueryKsymVars)
		if !ok {
			return guardUnknown, "no ksym_vars query", nil
		}
		_, err := kq.KsymVar(g.Target)
		switch {
		case errors.Is(err, ErrUnknown):
			return guardUnknown, err.Error(), nil
		case errors.Is(err, ErrKsymAbsent):
			return guardFalse, err.Error(), nil
		case err != nil:
			return 0, "", err
		}
		return guardTrue, "", nil
	case GuardType, GuardField:
		bp, ok := capsAs[BTFPresence](caps, QueryBTFPresence)
		if !ok {
			return guardUnknown, "no btf_presence query", nil
		}
		var present bool
		var err error
		if g.Kind == GuardType {
			present, err = bp.TypePresent(g.Target)
		} else {
			s, path, _ := strings.Cut(g.Target, ".")
			present, err = bp.FieldPresent(s, path)
		}
		switch {
		case errors.Is(err, ErrUnknown):
			return guardUnknown, err.Error(), nil
		case err != nil:
			return 0, "", err
		case !present:
			return guardFalse, g.Kind + " " + g.Target + " is absent", nil
		}
		return guardTrue, "", nil
	}
	return guardUnknown, "unknown guard kind " + g.Kind, nil
}

// guardsState folds a guarded list: false if any guard is false, else unknown
// if any is unknown, else true. why describes the deciding guard.
func guardsState(req *Requirements, gs []int, caps Capabilities) (int, string, error) {
	state, why := guardTrue, ""
	for _, g := range gs {
		s, w, err := guardState(req.Guards[g], caps)
		if err != nil {
			return 0, "", err
		}
		gd := req.Guards[g]
		switch s {
		case guardFalse:
			return guardFalse, fmt.Sprintf("guard %d (%s %s) is false: %s", g, gd.Kind, gd.Target, w), nil
		case guardUnknown:
			if state != guardUnknown {
				state, why = guardUnknown, fmt.Sprintf("guard %d (%s %s) is Unknown: %s", g, gd.Kind, gd.Target, w)
			}
		}
	}
	return state, why, nil
}

// checkKsymVars checks ksymvar rows: the loader declaration first (one Unmet
// per row), then the kernel answer. Keep Unmet Kind as literals for spec_test.
func checkKsymVars(req *Requirements, caps Capabilities) ([]Unmet, error) {
	decl := loaderOf(caps)
	kq, ok := capsAs[KernelKsymVars](caps, QueryKsymVars)
	var out []Unmet
	for _, v := range req.KsymVars {
		want := v.Class + " " + v.Slot
		switch decl.TypedKsym {
		case TypedKsymBTFID:
		case TypedKsymKallsymsAddr:
			out = append(out, Unmet{Kind: "typed_ksym_loader", Name: v.Name,
				Detail: "loader " + decl.Name + " declares typed_ksym kallsyms_addr"})
		default:
			out = append(out, Unmet{Kind: "typed_ksym_loader_unknown", Name: v.Name,
				Detail: "loader " + decl.Name + " does not declare typed_ksym"})
		}
		if !ok {
			out = append(out, Unmet{Kind: "ksymvar_unknown", Name: v.Name, Detail: "no ksym_vars query"})
			continue
		}
		got, err := kq.KsymVar(v.Name)
		switch {
		case errors.Is(err, ErrUnknown):
			out = append(out, Unmet{Kind: "ksymvar_unknown", Name: v.Name, Detail: err.Error()})
		case errors.Is(err, ErrKsymAbsent):
			if v.Bind == BindStrong {
				out = append(out, Unmet{Kind: "ksymvar", Name: v.Name,
					Detail: fmt.Sprintf("%v; the extern is strong (the object reads it as %s)", err, want)})
				continue
			}
			st, why, gerr := guardsState(req, v.Guards, caps)
			if gerr != nil {
				return nil, gerr
			}
			switch st {
			case guardFalse:
			case guardUnknown:
				out = append(out, Unmet{Kind: "ksymvar_unknown", Name: v.Name, Detail: fmt.Sprintf("%v, but %s", err, why)})
			default:
				out = append(out, Unmet{Kind: "ksymvar", Name: v.Name,
					Detail: fmt.Sprintf("%v, but no guard of the weak extern is confirmed false (the object reads it as %s)", err, want)})
			}
		case err != nil:
			return nil, err
		case got != want:
			out = append(out, Unmet{Kind: "ksymvar", Name: v.Name,
				Detail: fmt.Sprintf("the target's VAR is %s, the object reads it as %s", got, want)})
		}
	}
	return out, nil
}

// checkKFieldsGuarded checks the guarded kfield rows one by one. A definite
// mismatch with a guard confirmed false is excused only when the loader
// poisons the relocation of a missing field (COREPoisonsMissingField —
// otherwise kfield_unknown: the unexecuted branch still needs a loadable
// relocation). A guard false establishes the field's absence, so the excuse
// never covers a present field of another type.
func checkKFieldsGuarded(req *Requirements, caps Capabilities) ([]Unmet, error) {
	decl := loaderOf(caps)
	kt, haveTypes := capsAs[KernelTypes](caps, QueryKFields)
	var out []Unmet
	for i, k := range req.KFields {
		gs, guarded := req.KFieldGuards[i]
		if !guarded {
			continue
		}
		name := k.Struct + "." + k.Field + " (" + k.Type + ")"
		var diffs []string
		if haveTypes {
			d, err := kt.CheckKFields([]KField{k})
			if err != nil {
				return nil, err
			}
			if len(d) == 0 {
				continue
			}
			diffs = d
		}
		st, why, err := guardsState(req, gs, caps)
		if err != nil {
			return nil, err
		}
		switch {
		case st == guardFalse && decl.COREPoisonsMissingField:
		case st == guardFalse:
			out = append(out, Unmet{Kind: "kfield_unknown", Program: k.Program, Name: name,
				Detail: why + "; loader " + decl.Name + " does not declare core_poisons_missing_field"})
		case st == guardUnknown || !haveTypes:
			if why == "" {
				why = "no kfields query"
			}
			out = append(out, Unmet{Kind: "kfield_unknown", Program: k.Program, Name: name, Detail: why})
		default:
			for _, d := range diffs {
				out = append(out, Unmet{Kind: "kfield", Detail: d})
			}
		}
	}
	return out, nil
}

// checkKconfigs checks kconfig rows: the loader declaration, then the value.
func checkKconfigs(req *Requirements, caps Capabilities) ([]Unmet, error) {
	decl := loaderOf(caps)
	kc, ok := capsAs[KernelKconfig](caps, QueryKconfig)
	var out []Unmet
	for _, c := range req.Kconfigs {
		switch decl.Kconfig {
		case KconfigWeakZero:
		case KconfigStrongOnly:
			if c.Bind == BindWeak {
				out = append(out, Unmet{Kind: "kconfig_loader", Name: c.Name,
					Detail: "loader " + decl.Name + " declares kconfig strong_only and the extern is weak"})
			}
		default:
			out = append(out, Unmet{Kind: "kconfig_loader_unknown", Name: c.Name,
				Detail: "loader " + decl.Name + " does not declare kconfig"})
		}
		if !ok {
			out = append(out, Unmet{Kind: "kconfig_unknown", Name: c.Name, Detail: "no kconfig query"})
			continue
		}
		v, err := kc.KconfigValue(c.Name)
		switch {
		case errors.Is(err, ErrUnknown):
			out = append(out, Unmet{Kind: "kconfig_unknown", Name: c.Name, Detail: err.Error()})
		case errors.Is(err, ErrKconfigAbsent):
			if c.Bind == BindStrong {
				out = append(out, Unmet{Kind: "kconfig", Name: c.Name, Detail: err.Error() + "; the extern is strong"})
			}
		case err != nil:
			return nil, err
		default:
			if why := KconfigIncompatible(c.Type, v); why != "" {
				out = append(out, Unmet{Kind: "kconfig_type", Name: c.Name, Detail: why})
			}
		}
	}
	return out, nil
}

// KconfigIncompatible mirrors libbpf v1.7.0's bpf_object__process_kconfig_line
// (set_kcfg_value_tri / set_kcfg_value_str / parse_u64 / set_kcfg_value_num /
// is_kcfg_value_in_range — libbpf.c:2092-2298): it returns why the value
// would fail the load for an extern of type typ, or "". The first character
// selects the reading: y / n / m are tristate letters (bool refuses m; tristate
// and char accept all three; integer types refuse letters), '"' a string (no
// row type is a char array, so always refused), anything else an integer read
// by strtoull with base 0 and fully consumed — refused for bool and tristate
// (libbpf passes a number only to KCFG_INT and KCFG_CHAR) and range-checked
// otherwise. char is libbpf's KCFG_CHAR (every one-byte INT that is not BOOL —
// find_kcfg_type — so i8 / u8 are not row types); it is signed.
func KconfigIncompatible(typ, v string) string {
	if v == "" {
		return "the value is empty"
	}
	switch v[0] {
	case 'y', 'n', 'm':
		switch typ {
		case "bool":
			if v[0] == 'm' {
				return fmt.Sprintf("value %q implies tristate or char, the extern is bool", v)
			}
			return ""
		case "tristate", "char":
			return ""
		}
		return fmt.Sprintf("value %q implies bool, tristate or char, the extern is %s", v, typ)
	case '"':
		return fmt.Sprintf("value %s implies a char array, the extern is %s", v, typ)
	}
	num, ok := strtoull(v)
	if !ok {
		return fmt.Sprintf("value %q is not an integer", v)
	}
	if typ == "bool" || typ == "tristate" {
		return fmt.Sprintf("value %q implies an integer type, the extern is %s", v, typ)
	}
	bits, signed := 8, true
	if typ != "char" {
		b, _ := strconv.Atoi(typ[1:])
		bits, signed = b, typ[0] == 'i'
	}
	if bits == 64 {
		return ""
	}
	in := (num >> bits) == 0
	if signed {
		in = num+(uint64(1)<<(bits-1)) < uint64(1)<<bits
	}
	if !in {
		return fmt.Sprintf("value %q does not fit in %s", v, typ)
	}
	return ""
}

// strtoull is C strtoull(v, &end, 0) with *end == 0 and errno 0 required:
// leading white space, an optional sign (a minus negates modulo 2^64), 0x / 0X
// hexadecimal, a leading 0 octal, otherwise decimal; overflow fails (ERANGE).
func strtoull(v string) (uint64, bool) {
	i := 0
	for i < len(v) && (v[i] == ' ' || v[i] >= '\t' && v[i] <= '\r') {
		i++
	}
	neg := false
	if i < len(v) && (v[i] == '+' || v[i] == '-') {
		neg = v[i] == '-'
		i++
	}
	base := uint64(10)
	if i+2 < len(v) && v[i] == '0' && (v[i+1] == 'x' || v[i+1] == 'X') && hexDigit(v[i+2]) >= 0 {
		base, i = 16, i+2
	} else if i < len(v) && v[i] == '0' {
		base = 8
	}
	start := i
	var n uint64
	over := false
	for i < len(v) {
		d := hexDigit(v[i])
		if d < 0 || uint64(d) >= base {
			break
		}
		if n > (^uint64(0)-uint64(d))/base {
			over = true
		}
		n = n*base + uint64(d)
		i++
	}
	if i == start || i != len(v) || over {
		return 0, false
	}
	if neg {
		n = -n
	}
	return n, true
}

func hexDigit(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// KsymVar key: the VAR name. A text answer is the normalized type; a diffs
// answer records absence (its text).
func (c *RecordedCaps) KsymVar(name string) (string, error) {
	a, err := c.answer(QueryKsymVars, name)
	if err != nil {
		return "", err
	}
	if a.Diffs != nil {
		return "", fmt.Errorf("%s: %w", strings.Join(*a.Diffs, "; "), ErrKsymAbsent)
	}
	if a.Text == nil {
		return "", fmt.Errorf("recorded caps: %s %q is not a text or diffs answer", QueryKsymVars, name)
	}
	return *a.Text, nil
}

// KconfigValue key: CONFIG_<name>. A text answer is the raw value; a diffs
// answer records absence.
func (c *RecordedCaps) KconfigValue(name string) (string, error) {
	a, err := c.answer(QueryKconfig, name)
	if err != nil {
		return "", err
	}
	if a.Diffs != nil {
		return "", fmt.Errorf("%s: %w", strings.Join(*a.Diffs, "; "), ErrKconfigAbsent)
	}
	if a.Text == nil {
		return "", fmt.Errorf("recorded caps: %s %q is not a text or diffs answer", QueryKconfig, name)
	}
	return *a.Text, nil
}

// TypePresent key: type/<S>.
func (c *RecordedCaps) TypePresent(s string) (bool, error) {
	return c.boolean(QueryBTFPresence, BTFPresenceKey(GuardType, s))
}

// FieldPresent key: field/<S>.<path>.
func (c *RecordedCaps) FieldPresent(s, path string) (bool, error) {
	return c.boolean(QueryBTFPresence, BTFPresenceKey(GuardField, s+"."+path))
}

// recTextOrAbsent records a text answer, absence (sentinel) as diffs, Unknown
// and errors as such.
func (r *Recorder) recTextOrAbsent(q, key, v string, err, absent error) {
	switch {
	case errors.Is(err, ErrUnknown):
		r.put(q, key, Answer{Unknown: err.Error()})
	case errors.Is(err, absent):
		// The sentinel suffix is added back on read, so a round trip keeps the text.
		d := []string{strings.TrimSuffix(err.Error(), ": "+absent.Error())}
		r.put(q, key, Answer{Diffs: &d})
	case err != nil:
		r.put(q, key, Answer{Error: err.Error()})
	default:
		s := v
		r.put(q, key, Answer{Text: &s})
	}
}

// KsymVar forwards an available query (capsAs checks HasQuery first).
func (r *Recorder) KsymVar(name string) (string, error) {
	v, err := r.under.(KernelKsymVars).KsymVar(name)
	r.recTextOrAbsent(QueryKsymVars, name, v, err, ErrKsymAbsent)
	return v, err
}

// KconfigValue forwards an available query.
func (r *Recorder) KconfigValue(name string) (string, error) {
	v, err := r.under.(KernelKconfig).KconfigValue(name)
	r.recTextOrAbsent(QueryKconfig, name, v, err, ErrKconfigAbsent)
	return v, err
}

// TypePresent forwards an available query.
func (r *Recorder) TypePresent(s string) (bool, error) {
	v, err := r.under.(BTFPresence).TypePresent(s)
	return r.recBool(QueryBTFPresence, BTFPresenceKey(GuardType, s), v, err)
}

// FieldPresent forwards an available query.
func (r *Recorder) FieldPresent(s, path string) (bool, error) {
	v, err := r.under.(BTFPresence).FieldPresent(s, path)
	return r.recBool(QueryBTFPresence, BTFPresenceKey(GuardField, s+"."+path), v, err)
}
