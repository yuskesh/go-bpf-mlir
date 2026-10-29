// Package uprobeabi inspects the target binary of a uprobe: both gobpf's generate step (frontend) and the pre-load step (runtime)
// use it with the same rules. The rules are the same as bpf-mlir's (verdict version 4 — planned for v0.14.0):
//
//   - the binary's sha256 (the schema's binary_sha256 — it reads the same file it hashed)
//   - the symbol is exactly one FUNC (equal values in symtab and dynsym count as one) and lies in an executable PT_LOAD
//   - **the calling convention is decided by the DW_AT_language of the CU containing the target subprogram**: C89 0x01, C 0x02, C99 0x0c, C11 0x1d, C17 0x2c, C++ 0x04,
//     C++03 0x19, C++11 0x1a, C++14 0x21, C++17 0x2a and C++20 0x2b are SysV (go on to the argument check), **Go 0x16 is ABIError (Go's ABIInternal —
//     a different register assignment)**, absent or anything else is ABIUnknownError. If the subprogram has DW_AT_calling_convention and it is not 1 (DW_CC_normal),
//     ABIError. The abi verdict comes before the argument check (once it stops, the arguments are not read)
//   - the arguments are the type spellings of DW_TAG_formal_parameter (typedefs / qualifiers stripped to i8 to u64, ptr, strptr — the same as bpf-mlir's dwarfSpelling).
//     **A formal_parameter with DW_AT_variable_parameter true (a Go result) is not counted**
package uprobeabi

import (
	"crypto/sha256"
	"debug/dwarf"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// Info is the result of inspecting a binary's symbol.
type Info struct {
	SHA256     string   // the sha256 of the whole binary (hex)
	Params     []string // the parameter type spellings (results excluded — "" for an unreadable type)
	ParamNames []string
	FileOffset uint64 // the file offset of the symbol's entry (st_value − p_vaddr + p_offset — the uprobe attach Address)
	Language   int64  // the CU's DW_AT_language
	Producer   string // the CU's DW_AT_producer (to help the error text)
}

// ABIError means the target's calling convention is not SysV (a Go function, or not DW_CC_normal).
type ABIError struct{ Symbol, Detail string }

func (e *ABIError) Error() string {
	return fmt.Sprintf("uprobe target %s is not a SysV (C ABI) function: %s — its arguments are not in the registers uprobe.arg reads; probe a C function or a cgo //export entry instead", e.Symbol, e.Detail)
}

// ABIUnknownError means the calling convention cannot be determined (DW_AT_language absent or an unknown value).
type ABIUnknownError struct{ Symbol, Detail string }

func (e *ABIUnknownError) Error() string {
	return fmt.Sprintf("uprobe target %s: the calling convention cannot be determined (%s) — refusing rather than reading possibly wrong registers", e.Symbol, e.Detail)
}

// sysvLanguages are the DW_AT_language values treated as SysV that go on to the argument check (bpf-mlir's table).
var sysvLanguages = map[int64]string{
	0x01: "C89", 0x02: "C", 0x0c: "C99", 0x1d: "C11", 0x2c: "C17",
	0x04: "C++", 0x19: "C++03", 0x1a: "C++11", 0x21: "C++14", 0x2a: "C++17", 0x2b: "C++20",
}

const langGo = 0x16

// Inspect inspects the symbol in r (the whole binary). It checks the sha256, the symbol, the abi and the arguments in that order and returns the first mismatch as an error (an abi error is *ABIError /
// *ABIUnknownError).
func Inspect(r io.ReaderAt, symbol string) (*Info, error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(r, 0, 1<<62)); err != nil {
		return nil, fmt.Errorf("reading the binary: %w", err)
	}
	info := &Info{SHA256: hex.EncodeToString(h.Sum(nil))}
	f, err := elf.NewFile(r)
	if err != nil {
		return info, fmt.Errorf("not an ELF binary: %w", err)
	}
	off, err := fileOffset(f, symbol)
	if err != nil {
		return info, err
	}
	info.FileOffset = off
	d, err := f.DWARF()
	if err != nil {
		return info, &ABIUnknownError{symbol, "the binary has no DWARF: " + err.Error()}
	}
	rd := d.Reader()
	var lang any
	var producer string
	for {
		e, err := rd.Next()
		if err != nil {
			return info, fmt.Errorf("reading DWARF: %w", err)
		}
		if e == nil {
			return info, &ABIUnknownError{symbol, "no DW_TAG_subprogram named " + symbol + " in the DWARF"}
		}
		if e.Tag == dwarf.TagCompileUnit {
			lang = e.Val(dwarf.AttrLanguage)
			producer, _ = e.Val(dwarf.AttrProducer).(string)
			continue
		}
		if e.Tag != dwarf.TagSubprogram || e.Val(dwarf.AttrName) != symbol || !e.Children {
			continue
		}
		info.Producer = producer
		l, ok := lang.(int64)
		switch {
		case !ok:
			return info, &ABIUnknownError{symbol, "the compilation unit has no DW_AT_language"}
		case l == langGo:
			info.Language = l
			return info, &ABIError{symbol, fmt.Sprintf("its compilation unit is Go (DW_AT_language 0x16, producer %q — Go's ABIInternal passes arguments in RAX, RBX, RCX, …)", producer)}
		}
		if _, sysv := sysvLanguages[l]; !sysv {
			return info, &ABIUnknownError{symbol, fmt.Sprintf("DW_AT_language 0x%x is not a known C / C++ language", l)}
		}
		info.Language = l
		if cc, ok := e.Val(dwarf.AttrCalling).(int64); ok && cc != 1 {
			return info, &ABIError{symbol, fmt.Sprintf("DW_AT_calling_convention is %d, not DW_CC_normal (1)", cc)}
		}
		for {
			c, err := rd.Next()
			if err != nil {
				return info, fmt.Errorf("reading DWARF: %w", err)
			}
			if c == nil || c.Tag == 0 {
				return info, nil
			}
			if c.Tag == dwarf.TagFormalParameter {
				if vp, _ := c.Val(dwarf.AttrVarParam).(bool); !vp {
					name, _ := c.Val(dwarf.AttrName).(string)
					typ := ""
					if o, ok := c.Val(dwarf.AttrType).(dwarf.Offset); ok {
						if t, err := d.Type(o); err == nil {
							typ = spelling(t)
						}
					}
					info.Params = append(info.Params, typ)
					info.ParamNames = append(info.ParamNames, name)
				}
			}
			if c.Children {
				rd.SkipChildren()
			}
		}
	}
}

// IsABI reports whether err is a calling-convention error (a Go function, or undeterminable).
func IsABI(err error) bool {
	var a *ABIError
	var u *ABIUnknownError
	return errors.As(err, &a) || errors.As(err, &u)
}

// fileOffset returns the file offset of the entry of the symbol (exactly one FUNC) (inside an executable PT_LOAD — the same computation as bpf-mlir's uprobecheck).
func fileOffset(f *elf.File, name string) (uint64, error) {
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
		return 0, fmt.Errorf("the binary has %d FUNC symbols named %s (want exactly one)", len(vals), name)
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD && p.Flags&elf.PF_X != 0 && p.Vaddr <= vals[0] && vals[0] < p.Vaddr+p.Memsz {
			return offsetIn(vals[0], p.Vaddr, p.Off), nil
		}
	}
	return 0, fmt.Errorf("%s (0x%x) is not in an executable PT_LOAD of the binary", name, vals[0])
}

// spelling returns the type spelling with typedefs / qualifiers stripped (the same as dwarfSpelling in bpf-mlir's go/requirements): integers are i8 to u64, a single-level
// pointer to an 8-bit char is strptr, other pointers are ptr, and "" if unreadable.
func spelling(t dwarf.Type) string {
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

// Locate returns only the binary's sha256 and the file offset of the entry of the symbol (exactly one FUNC) (it does not read the calling convention or arguments). gobpf's runtime
// uses it to attach — the calling-convention and argument checks are left to the bpf-mlir v0.14.0 gate (bindrt's Precheck — verdict version 4, uprobearg_abi).
func Locate(r io.ReaderAt, symbol string) (sha string, offset uint64, err error) {
	h := sha256.New()
	if _, err := io.Copy(h, io.NewSectionReader(r, 0, 1<<62)); err != nil {
		return "", 0, fmt.Errorf("reading the binary: %w", err)
	}
	sha = hex.EncodeToString(h.Sum(nil))
	f, err := elf.NewFile(r)
	if err != nil {
		return sha, 0, fmt.Errorf("not an ELF binary: %w", err)
	}
	offset, err = fileOffset(f, symbol)
	return sha, offset, err
}
