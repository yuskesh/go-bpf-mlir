package requirements

import (
	"debug/elf"
	"errors"
	"fmt"
	"sort"
	"strings"
)

// SleepableMinVersion is the first format with the sleepable row.
const SleepableMinVersion = 32

// SleepableCaps answers whether a program type × expected_attach_type pair can
// be loaded with BPF_F_SLEEPABLE (kernel can_be_sleepable). (true, nil) and
// (false, nil) are known answers; an error wrapping ErrUnknown is Unknown.
//
// The probe must separate the reasons a sleepable load is refused: only "Program
// of this type cannot be sleepable" is false. A per-function allowlist refusal
// ("<name> is not sleepable"), a permission refusal and an absent probe target
// are Unknown — the kernel still refuses those loudly at load, so Unknown does
// not block.
type SleepableCaps interface {
	CheckSleepable(programType, attachType string) (bool, error)
}

// sleepableKey is the whole recorded / cached key, so a fentry answer never
// answers fexit or another attach type.
func sleepableKey(programType, attachType string) string { return programType + "/" + attachType }

func validSleepableKey(k string) bool {
	p, a, ok := strings.Cut(k, "/")
	return ok && p != "" && a != "" && !strings.ContainsAny(k, " \t\n") && !strings.Contains(a, "/")
}

// checkSleepable evaluates one sleepable trace_fentry attach: false blocks as
// sleepable_type, Unknown (no probe, unknown, key missing) as
// sleepable_type_unknown, which does not block.
func checkSleepable(a Attach, programType string, caps Capabilities) ([]Unmet, error) {
	unknown := func(detail string) ([]Unmet, error) {
		u := Unmet{Kind: "sleepable_type_unknown", Program: a.Program, Name: a.Target, Detail: detail}
		return []Unmet{u}, nil
	}
	q, ok := capsAs[SleepableCaps](caps, QuerySleepable)
	if !ok {
		return unknown("no sleepable probe")
	}
	have, err := q.CheckSleepable(programType, a.AttachType)
	if errors.Is(err, ErrUnknown) {
		return unknown(err.Error())
	}
	if err != nil {
		return nil, err
	}
	if !have {
		u := Unmet{Kind: "sleepable_type", Program: a.Program, Name: a.Target,
			Detail: "the target kernel cannot load program type " + programType + " with attach type " + a.AttachType + " sleepable"}
		return []Unmet{u}, nil
	}
	return nil, nil
}

// CheckSleepable returns the recorded answer; the key is <programType>/<attachType>.
func (c *RecordedCaps) CheckSleepable(programType, attachType string) (bool, error) {
	if r, err, use := c.privileged(QuerySleepable); !use {
		if err != nil {
			return false, err
		}
		if !reprobeHas(r, QuerySleepable) {
			return false, noReprobe(QuerySleepable)
		}
		return r.(SleepableCaps).CheckSleepable(programType, attachType)
	}
	return c.boolean(QuerySleepable, sleepableKey(programType, attachType))
}

// CheckSleepable forwards an available query and records the answer.
func (r *Recorder) CheckSleepable(programType, attachType string) (bool, error) {
	q, ok := capsAs[SleepableCaps](r.under, QuerySleepable)
	if !ok {
		return r.recBool(QuerySleepable, sleepableKey(programType, attachType), false, unknownErr("no sleepable probe"))
	}
	v, err := q.CheckSleepable(programType, attachType)
	return r.recBool(QuerySleepable, sleepableKey(programType, attachType), v, err)
}

// checkRecordedSleepable rejects a sleepable_types query in a caps record older
// than the format that introduced it and malformed keys / non-value answers.
func checkRecordedSleepable(c *RecordedCaps) error {
	for _, queries := range []map[string]map[string]Answer{c.Queries, c.PrivilegedQueries} {
		answers, present := queries[QuerySleepable]
		if !present {
			continue
		}
		if c.Format != RecordedFormat {
			return keyNewerFormat("caps: query %q is new in %q, but the format is %q", QuerySleepable, RecordedFormat, c.Format)
		}
		keys := make([]string, 0, len(answers))
		for k := range answers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			a := answers[k]
			if !validSleepableKey(k) {
				return fmt.Errorf("caps: sleepable_types: key %q is not <program type>/<attach type>", k)
			}
			if a.Value == nil && a.Unknown == "" && a.Error == "" {
				return fmt.Errorf("caps: sleepable_types %q is not a value answer", k)
			}
		}
	}
	return nil
}

// programTypeOf returns the program row's type spelling for prog, or "".
func programTypeOf(req *Requirements, prog string) string {
	for _, p := range req.Programs {
		if p.Symbol == prog {
			return p.ProgType
		}
	}
	return ""
}

const sleepableSectionPrefix = "fentry.s/"

// checkSleepableSections ties the sleepable row to the ELF section that decides
// the real load flag (cilium sets BPF_F_SLEEPABLE from the section name): a
// program in section fentry.s/<fn> needs its trace_fentry attach row for <fn>
// plus a sleepable row; a sleepable row needs the program in that section. Parse
// cannot see sections, so a stale or hand-edited row would otherwise be trusted.
func checkSleepableSections(f *elf.File, req *Requirements) error {
	rows := map[string]Attach{}
	for _, a := range req.Attaches {
		if a.Sleepable {
			rows[a.Program] = a
		}
	}
	has := len(rows) > 0
	for _, s := range f.Sections {
		if strings.HasPrefix(s.Name, sleepableSectionPrefix) {
			has = true
		}
	}
	if !has {
		return nil
	}
	syms, err := f.Symbols()
	if err != nil {
		return fmt.Errorf("sleepable: reading the symbol table: %w", err)
	}
	// Every FUNC in a fentry.s/ section is loaded with BPF_F_SLEEPABLE whatever its
	// name: it must be a declared program (so the checks below see it) — a renamed
	// or hidden entry would otherwise escape the sleepable-row requirement — and a
	// fentry.s/ section must hold at least one declared program.
	declared := map[string]bool{}
	for _, p := range req.Programs {
		declared[p.Symbol] = true
	}
	holds := map[string]bool{}
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Section == elf.SHN_UNDEF || int(s.Section) >= len(f.Sections) {
			continue
		}
		sec := f.Sections[s.Section].Name
		if !strings.HasPrefix(sec, sleepableSectionPrefix) {
			continue
		}
		if !declared[s.Name] {
			return fmt.Errorf("sleepable: function %q in section %q (loaded with BPF_F_SLEEPABLE) is not a program declared in the requirements", s.Name, sec)
		}
		holds[sec] = true
	}
	for _, s := range f.Sections {
		if strings.HasPrefix(s.Name, sleepableSectionPrefix) && !holds[s.Name] {
			return fmt.Errorf("sleepable: section %q holds no function declared as a program in the requirements", s.Name)
		}
	}
	entry := map[string]string{} // program -> its FUNC's section name
	for _, s := range syms {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC || s.Section == elf.SHN_UNDEF || int(s.Section) >= len(f.Sections) {
			continue
		}
		for _, p := range req.Programs {
			if p.Symbol == s.Name {
				entry[p.Symbol] = f.Sections[s.Section].Name
			}
		}
	}
	for _, p := range req.Programs {
		sec := entry[p.Symbol]
		if !strings.HasPrefix(sec, sleepableSectionPrefix) {
			continue
		}
		a, ok := rows[p.Symbol]
		if !ok {
			return fmt.Errorf("sleepable: program %s is in section %q (loaded with BPF_F_SLEEPABLE) but the requirements have no sleepable row for it", p.Symbol, sec)
		}
		if want := sleepableSectionPrefix + a.Target; sec != want {
			return fmt.Errorf("sleepable: program %s is in section %q but its trace_fentry attach row names %q (want section %q)", p.Symbol, sec, a.Target, want)
		}
	}
	for prog, a := range rows {
		sec, ok := entry[prog]
		if !ok {
			return fmt.Errorf("sleepable: the sleepable row names program %s, which has no FUNC in the object", prog)
		}
		if !strings.HasPrefix(sec, sleepableSectionPrefix) {
			return fmt.Errorf("sleepable: the sleepable row for program %s (attach %s) but the program is in section %q, not %s<function>", prog, a.Target, sec, sleepableSectionPrefix)
		}
	}
	return nil
}
