package requirements

import (
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// UprobeBinaries supplies the already-hashed binary descriptor used for attach,
// so checking and attaching see the same inode. Paths are loader inputs.
// Missing capabilities produce blocking binary_unknown.
type UprobeBinaries interface {
	UprobeBinary(program string) (io.ReaderAt, error)
}

// checkUprobe checks architecture/context offsets, binary SHA-256, executable
// PT_LOAD FUNC symbols and DWARF argument types. It does not use kallsyms or
// kernel FUNC_PROTO evidence. Every Unknown blocks loading.
func checkUprobe(a Attach, caps Capabilities) ([]Unmet, error) {
	out, _, err := checkArchAndCtx(a, caps)
	if err != nil {
		return nil, err
	}
	f, out, err := openUprobeBinary(a, caps, out)
	if err != nil || f == nil {
		return out, err
	}
	source := &uprobeDWARFSource{body: f, caps: caps, program: a.Program}
	return append(out, uprobeTargetUnmets(f, a, a.Target, a.AttachType == "uretprobe", source)...), nil
}

// openUprobeBinary checks binary SHA-256 and reads ELF for single/multi uprobes
// and USDT. Failure returns nil ELF plus Unmet named a.Target; callers must
// then skip symbol and type checks.
func openUprobeBinary(a Attach, caps Capabilities, out []Unmet) (*elf.File, []Unmet, error) {
	if a.BinarySHA256 == "" {
		return nil, nil, fmt.Errorf("program %s: %s attach row without a binary row", a.Program, a.AttachType)
	}
	ub, ok := capsAs[UprobeBinaries](caps, QueryUprobeBin)
	if !ok {
		return nil, append(out, Unmet{Kind: "binary_unknown", Program: a.Program, Name: a.Target, Detail: "no binary given"}), nil
	}
	r, err := ub.UprobeBinary(a.Program)
	if err != nil {
		return nil, append(out, Unmet{Kind: "binary_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()}), nil
	}
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(r, 0, 1<<62)); err != nil {
		return nil, append(out, Unmet{Kind: "binary_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()}), nil
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != a.BinarySHA256 {
		// A different binary makes subsequent symbol/type checks meaningless.
		return nil, append(out, Unmet{Kind: "binary", Program: a.Program, Name: a.Target,
			Detail: fmt.Sprintf("the binary's SHA-256 is %s, but the object was built for %s", got, a.BinarySHA256)}), nil
	}
	f, err := elf.NewFile(r)
	if err != nil {
		return nil, append(out, Unmet{Kind: "binary_unknown", Program: a.Program, Name: a.Target, Detail: err.Error()}), nil
	}
	return f, out, nil
}

// uprobeTargetUnmets checks one target symbol, including each multi mtarget.
// ret checks return-family ABI even without argument rows.
func uprobeTargetUnmets(f *elf.File, a Attach, target string, ret bool, source ...*uprobeDWARFSource) []Unmet {
	var out []Unmet
	if d := uprobeSymbol(f, target); d != "" {
		out = append(out, Unmet{Kind: "uprobe_symbol", Program: a.Program, Name: target, Detail: d})
	}
	var data *dwarf.Data
	var sourceErr error
	if len(source) > 0 && (ret || len(a.UprobeArgs) > 0) {
		data, sourceErr = source[0].read()
		if source[0].kind != "" {
			var u Unmet
			switch source[0].kind {
			case "uprobe_debug_build_id":
				u = Unmet{Kind: "uprobe_debug_build_id"}
			case "uprobe_debug_crc":
				u = Unmet{Kind: "uprobe_debug_crc"}
			}
			u.Program, u.Name, u.Detail = a.Program, target, sourceErr.Error()
			return append(out, u)
		}
	}
	rawPointers := map[int]bool{}
	for _, arg := range a.UprobeArgs {
		if arg.Type == "ptr" {
			rawPointers[arg.N] = true
		}
	}
	readSubprogram := func(parameters bool) (dwarfSubprogram, error) {
		if sourceErr != nil {
			return dwarfSubprogram{}, sourceErr
		}
		if len(source) > 0 {
			return dwarfSubprogramFromData(f, data, target, parameters, rawPointers)
		}
		return dwarfSubprogramAt(f, target, parameters, rawPointers)
	}
	// Return probes read SysV rax, even without argument rows. Require a C-family
	// CU language. Go yields uretprobe_abi; missing/other language or missing
	// subprogram evidence yields uretprobe_abi_unknown.
	if ret {
		sp, err := readSubprogram(false)
		if err != nil {
			return append(out, Unmet{Kind: "uretprobe_abi_unknown", Program: a.Program, Name: target,
				Detail: fmt.Sprintf("the calling convention of %s cannot be told (%v)", target, err)})
		}
		switch v, detail := uretprobeABI(target, sp); v {
		case abiNotSysV:
			return append(out, Unmet{Kind: "uretprobe_abi", Program: a.Program, Name: target, Detail: detail})
		case abiUnknown:
			return append(out, Unmet{Kind: "uretprobe_abi_unknown", Program: a.Program, Name: target, Detail: detail})
		}
		return out
	}
	if len(a.UprobeArgs) == 0 {
		return out
	}
	sp, err := readSubprogram(true)
	// uprobe.arg reads SysV registers. Reject a non-C-family CU language
	// before checking argument types.
	if err == nil {
		switch v, detail := uprobeABI(target, sp); v {
		case abiNotSysV:
			return append(out, Unmet{Kind: "uprobearg_abi", Program: a.Program, Name: target, Detail: detail})
		case abiUnknown:
			return append(out, Unmet{Kind: "uprobearg_abi_unknown", Program: a.Program, Name: target, Detail: detail})
		}
	}
	params := sp.params
	for _, k := range a.UprobeArgs {
		name := fmt.Sprintf("%d of %s (%s)", k.N, target, k.Type)
		if err != nil {
			out = append(out, Unmet{Kind: "uprobearg_unknown", Program: a.Program, Name: name, Detail: err.Error()})
			continue
		}
		if k.N > len(params) {
			out = append(out, Unmet{Kind: "uprobearg", Program: a.Program, Name: name,
				Detail: fmt.Sprintf("%s takes %d arguments in the binary's DWARF, but the object reads argument %d", target, len(params), k.N)})
			continue
		}
		p := params[k.N-1]
		if k.Type == "ptr" {
			// Only the new request uses direct DIE evidence; legacy spellings stay intact.
			p.typ = p.pointer
		}
		if p.typ == "" {
			out = append(out, Unmet{Kind: "uprobearg_unknown", Program: a.Program, Name: name, Detail: "argument " + p.name + " has a type this check cannot read"})
			continue
		}
		if p.typ != k.Type {
			out = append(out, Unmet{Kind: "uprobearg", Program: a.Program, Name: name,
				Detail: fmt.Sprintf("argument %d (%s) of %s is %s in the binary's DWARF, but the object reads it as %s", k.N, ArgName(p.name), target, p.typ, k.Type)})
		}
	}
	return out
}

// uprobeSymbol requires exactly one FUNC in an executable PT_LOAD. It returns
// a mismatch message, or an empty string on success.
func uprobeSymbol(f *elf.File, name string) string {
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	var vals []uint64
	seen := map[uint64]bool{}
	for _, s := range append(syms, dyn...) {
		if s.Name == name && elf.ST_TYPE(s.Info) == elf.STT_FUNC && !seen[s.Value] {
			seen[s.Value] = true
			vals = append(vals, s.Value)
		}
	}
	if len(vals) != 1 {
		return fmt.Sprintf("the binary has %d FUNC symbols named %s (want exactly one)", len(vals), name)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Vaddr <= vals[0] && vals[0] < p.Vaddr+p.Memsz {
			return ""
		}
	}
	return fmt.Sprintf("%s (0x%x) is not in an executable PT_LOAD of the binary", name, vals[0])
}

type dwarfParam struct{ name, typ, pointer string }

// dwarfSubprogram retains formal parameters (excluding true
// DW_AT_variable_parameter results), CU language/producer and calling convention
// (-1 when absent).
type dwarfSubprogram struct {
	params   []dwarfParam
	lang     int64 // DW_AT_language, or -1 when absent.
	producer string
	cc       int64
}

// SysVLanguages lists supported C/C++ CU DW_AT_language values. Others block
// argument checking: Go 0x16/ABIInternal yields uprobearg_abi; Rust, Objective-C
// and missing/unknown language yield uprobearg_abi_unknown. See
// docs/requirements_format.md section 6.
var SysVLanguages = map[int64]string{
	0x01: "C89", 0x02: "C", 0x0c: "C99", 0x1d: "C11", 0x2c: "C17",
	0x04: "C_plus_plus", 0x19: "C_plus_plus_03", 0x1a: "C_plus_plus_11", 0x21: "C_plus_plus_14", 0x2a: "C_plus_plus_17", 0x2b: "C_plus_plus_20",
}

// dwLangGo is DW_LANG_Go.
const dwLangGo = 0x16

// uprobeABI outcomes.
const (
	abiSysV    = iota // C-family CU: continue to argument checking.
	abiNotSysV        // Known non-SysV (Go or nonnormal calling convention): uprobearg_abi.
	abiUnknown        // Missing/unknown language: uprobearg_abi_unknown.
)

// uprobeABI returns a blocking outcome and message unless the target ABI
// can be treated as SysV.
func uprobeABI(target string, sp dwarfSubprogram) (verdict int, detail string) {
	if sp.cc >= 0 && sp.cc != 1 { // DW_CC_normal
		return abiNotSysV, fmt.Sprintf("%s has DW_AT_calling_convention %d (not DW_CC_normal) — uprobe.arg reads the SysV argument registers", target, sp.cc)
	}
	if _, ok := SysVLanguages[sp.lang]; ok {
		return abiSysV, ""
	}
	prod := ""
	if sp.producer != "" {
		prod = fmt.Sprintf(" (producer %q)", sp.producer)
	}
	if sp.lang == dwLangGo {
		return abiNotSysV, fmt.Sprintf("%s is a Go function%s — Go's ABIInternal passes arguments in registers that uprobe.arg (SysV) does not read; target a cgo //export C entry instead", target, prod)
	}
	if sp.lang < 0 {
		return abiUnknown, fmt.Sprintf("the compilation unit of %s has no DW_AT_language%s — the calling convention cannot be told", target, prod)
	}
	return abiUnknown, fmt.Sprintf("the compilation unit of %s has DW_AT_language 0x%x%s, which is not C or C++ — the calling convention cannot be told", target, sp.lang, prod)
}

// uretprobeABI uses the same ABI decision as uprobeABI with return-register text.
func uretprobeABI(target string, sp dwarfSubprogram) (verdict int, detail string) {
	v, _ := uprobeABI(target, sp)
	prod := ""
	if sp.producer != "" {
		prod = fmt.Sprintf(" (producer %q)", sp.producer)
	}
	switch {
	case v == abiSysV:
		return v, ""
	case sp.cc >= 0 && sp.cc != 1:
		return v, fmt.Sprintf("%s has DW_AT_calling_convention %d (not DW_CC_normal) — probe.retval reads the SysV return value register", target, sp.cc)
	case sp.lang == dwLangGo:
		return v, fmt.Sprintf("%s is a Go function%s — Go's ABIInternal returns results in RAX, RBX, … (probe.retval reads the SysV return value register only); target a cgo //export C entry instead", target, prod)
	case sp.lang < 0:
		return v, fmt.Sprintf("the compilation unit of %s has no DW_AT_language%s — the calling convention cannot be told", target, prod)
	}
	return v, fmt.Sprintf("the compilation unit of %s has DW_AT_language 0x%x%s, which is not C or C++ — the calling convention cannot be told", target, sp.lang, prod)
}

// dwarfSubprogramOf reads CU language/producer and calling convention without
// requiring parameters, so childless no-argument functions remain discoverable.
// Missing DWARF or subprogram evidence is an error.
func dwarfSubprogramOf(f *elf.File, name string) (dwarfSubprogram, error) {
	return dwarfSubprogramAt(f, name, false)
}

// dwarfParams reads the unique definition at the already-checked FUNC address.
func dwarfParams(f *elf.File, name string) (dwarfSubprogram, error) {
	return dwarfSubprogramAt(f, name, true)
}

// dwarfSubprogramAt requires direct address evidence with no fallback to
// names, ranges or specification references.
func dwarfSubprogramAt(f *elf.File, name string, parameters bool, rawPointers ...map[int]bool) (dwarfSubprogram, error) {
	d, err := f.DWARF()
	if err != nil {
		return dwarfSubprogram{}, fmt.Errorf("no DWARF: %w", err)
	}
	return dwarfSubprogramFromData(f, d, name, parameters, rawPointers...)
}

// Addresses always come from the checked body, even when data is separate.
func dwarfSubprogramFromData(f *elf.File, d *dwarf.Data, name string, parameters bool, rawPointers ...map[int]bool) (dwarfSubprogram, error) {
	if detail := uprobeSymbol(f, name); detail != "" {
		return dwarfSubprogram{}, errors.New("cannot resolve DWARF address: " + detail)
	}
	syms, _ := f.Symbols()
	dyn, _ := f.DynamicSymbols()
	var address uint64
	for _, s := range append(syms, dyn...) {
		if s.Name == name && elf.ST_TYPE(s.Info) == elf.STT_FUNC {
			address = s.Value
			break
		}
	}
	rd := d.Reader()
	lang, producer := int64(-1), ""
	var selected dwarfSubprogram
	matches := 0
	for {
		e, err := rd.Next()
		if err != nil {
			return dwarfSubprogram{}, err
		}
		if e == nil {
			break
		}
		if e.Tag == dwarf.TagCompileUnit {
			lang, producer = -1, ""
			if v, ok := e.Val(dwarf.AttrLanguage).(int64); ok {
				lang = v
			}
			producer, _ = e.Val(dwarf.AttrProducer).(string)
			continue
		}
		if e.Tag != dwarf.TagSubprogram {
			continue
		}
		if declaration, _ := e.Val(dwarf.AttrDeclaration).(bool); declaration {
			continue
		}
		pc, ok := e.Val(dwarf.AttrLowpc).(uint64)
		if !ok || pc != address {
			continue
		}
		matches++
		sp := dwarfSubprogram{lang: lang, producer: producer, cc: -1}
		if cc, ok := e.Val(dwarf.AttrCalling).(int64); ok {
			sp.cc = cc
		}
		if e.Children {
			for {
				c, err := rd.Next()
				if err != nil {
					return dwarfSubprogram{}, err
				}
				if c == nil || c.Tag == 0 {
					break
				}
				if parameters && c.Tag == dwarf.TagFormalParameter {
					result, _ := c.Val(dwarf.AttrVarParam).(bool)
					if !result {
						pn, _ := c.Val(dwarf.AttrName).(string)
						param := dwarfParam{name: pn}
						if off, ok := c.Val(dwarf.AttrType).(dwarf.Offset); ok {
							if len(rawPointers) > 0 && rawPointers[0][len(sp.params)+1] {
								param.pointer = dwarfPointerSpelling(d, off)
							} else if t, err := d.Type(off); err == nil {
								param.typ = dwarfSpelling(t)
							}
						}
						sp.params = append(sp.params, param)
					}
				}
				if c.Children {
					rd.SkipChildren()
				}
			}
		}
		selected = sp
	}
	if matches != 1 {
		return dwarfSubprogram{}, fmt.Errorf("DWARF has %d non-declaration DW_TAG_subprogram definitions at %s (0x%x), want exactly one", matches, name, address)
	}
	return selected, nil
}

// dwarfSpelling unwraps typedefs/qualifiers. Integers use i8..u64; pointers use
// ptr except one pointer to qualified/typedef-wrapped 8-bit char, signed char
// or unsigned char, which is strptr. char** and void* remain ptr, never strings.
// Unreadable types return an empty spelling.
func dwarfSpelling(t dwarf.Type) string {
	for {
		switch u := t.(type) {
		case *dwarf.TypedefType:
			t = u.Type
			continue
		case *dwarf.QualType:
			t = u.Type
			continue
		case *dwarf.UintType:
			return fmt.Sprintf("u%d", u.ByteSize*8)
		case *dwarf.IntType:
			return fmt.Sprintf("i%d", u.ByteSize*8)
		case *dwarf.UcharType:
			return "u8"
		case *dwarf.CharType:
			return "i8"
		case *dwarf.PtrType:
			if isChar8(u.Type) {
				return "strptr"
			}
			return "ptr"
		}
		return ""
	}
}

// isChar8 unwraps typedef/const/volatile and accepts only 8-bit DWARF character
// types. Void, pointers (including the first target of char**) and other widths
// are false.
func isChar8(t dwarf.Type) bool {
	for {
		switch u := t.(type) {
		case *dwarf.TypedefType:
			t = u.Type
			continue
		case *dwarf.QualType:
			t = u.Type
			continue
		case *dwarf.CharType:
			return u.ByteSize == 1
		case *dwarf.UcharType:
			return u.ByteSize == 1
		}
		return false
	}
}

// ArgName uses 'unnamed' for parameters without a name, including function
// pointers and DWARF parameters. TestArgName fixes this spelling, also copied
// byte-for-byte by bml.
func ArgName(name string) string {
	if name == "" {
		return "unnamed"
	}
	return name
}
