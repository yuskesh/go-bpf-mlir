package requirements

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// USDT points are systemtap sys/sdt.h notes in .note.stapsdt (owner stapsdt, type 3).
// Each descriptor contains pc, the link-time .stapsdt.base address, the semaphore
// address (zero if absent), and NUL-terminated provider, name and argument strings.
// Arguments are space-separated <[-]size>@<location> descriptions. The binary's
// compiler chooses each location; programs do not know it. Loaders read notes
// through UprobeBinary's ReaderAt and construct specs as required by
// docs/requirements_format.md. Matching checks points, semaphores, argument counts,
// sizes, signedness and loader support for location spellings.

// usdtNoteType is NT_STAPSDT.
const usdtNoteType = 3

// USDTSpecMapPrefix prefixes per-program compiler spec maps: __ebpf_usdt_spec_<program>.
const USDTSpecMapPrefix = "__ebpf_usdt_spec_"

// USDTPoint describes one note point.
type USDTPoint struct {
	PC, Base, Semaphore uint64
	Provider, Name      string
	Args                string // Space-separated <[-]size>@<location> argument descriptions.
}

// ReadUSDTPoints returns stapsdt points in note order. A missing section is empty; malformed notes fail.
func ReadUSDTPoints(f *elf.File) ([]USDTPoint, error) {
	addr := 8
	if f.Class == elf.ELFCLASS32 {
		addr = 4
	}
	var out []USDTPoint
	for _, s := range f.Sections {
		if s.Type != elf.SHT_NOTE {
			continue
		}
		data, err := s.Data()
		if err != nil {
			return nil, fmt.Errorf("section %s: %w", s.Name, err)
		}
		for p := 0; p < len(data); {
			if len(data)-p < 12 {
				return nil, fmt.Errorf("section %s: a note header is cut at offset %d", s.Name, p)
			}
			namesz, descsz, typ := int(f.ByteOrder.Uint32(data[p:])), int(f.ByteOrder.Uint32(data[p+4:])), f.ByteOrder.Uint32(data[p+8:])
			p += 12
			nameEnd, descOff := p+namesz, p+align4(namesz)
			descEnd := descOff + descsz
			if namesz < 0 || descsz < 0 || nameEnd > len(data) || descEnd > len(data) {
				return nil, fmt.Errorf("section %s: a note runs past the section at offset %d", s.Name, p-12)
			}
			name := strings.TrimRight(string(data[p:nameEnd]), "\x00")
			desc := data[descOff:descEnd]
			p = descOff + align4(descsz)
			if name != "stapsdt" || typ != usdtNoteType {
				continue
			}
			pt, err := parseUSDTDesc(desc, addr, f.ByteOrder)
			if err != nil {
				return nil, fmt.Errorf("section %s: %w", s.Name, err)
			}
			out = append(out, pt)
		}
	}
	return out, nil
}

func align4(n int) int { return (n + 3) &^ 3 }

// parseUSDTDesc reads pc, base, semaphore and three NUL-terminated strings.
func parseUSDTDesc(d []byte, addr int, bo binary.ByteOrder) (USDTPoint, error) {
	if len(d) < 3*addr {
		return USDTPoint{}, errors.New("a stapsdt note's description is shorter than its three addresses")
	}
	word := func(i int) uint64 {
		if addr == 4 {
			return uint64(bo.Uint32(d[i*4:]))
		}
		return bo.Uint64(d[i*8:])
	}
	pt := USDTPoint{PC: word(0), Base: word(1), Semaphore: word(2)}
	rest := d[3*addr:]
	var strs [3]string
	for i := range strs {
		j := 0
		for j < len(rest) && rest[j] != 0 {
			j++
		}
		if j == len(rest) {
			return USDTPoint{}, fmt.Errorf("the stapsdt note at pc 0x%x does not end its provider, name and arguments with NUL", pt.PC)
		}
		strs[i], rest = string(rest[:j]), rest[j+1:]
	}
	pt.Provider, pt.Name, pt.Args = strs[0], strs[1], strs[2]
	return pt, nil
}

// USDTArgSpec describes one <[-]size>@<location> argument. Kind is reg (%reg),
// deref (off(%reg), with optional offset), or const ($imm).
type USDTArgSpec struct {
	Size   int  // 1, 2, 4 or 8 bytes.
	Signed bool // Negative size spelling, such as -4@.
	Kind   string
	Reg    string // Register name without % for reg and deref.
	Off    int64  // Dereference offset or constant value.
}

// usdtX86Regs maps supported x86_64 location names to pt_regs fields, including
// general-purpose 64/32/16/8-bit names from libbpf tools/lib/bpf/usdt.c reg_map.
// Exclude rip/eip: off(%rip) is relative to the following instruction, whereas
// pt_regs.ip points to the probe itself.
var usdtX86Regs = map[string]string{}

// usdtX86RegIndex maps note register names to spec register indices. The ABI uses
// usdt.c reg_map order without rip: ax=0, bx=1, cx=2, dx=3, si=4, di=5, bp=6,
// sp=7 and r8=8 through r15=15. Tests compare this with abi/uapi.tsv usdtreg.
var usdtX86RegIndex = map[string]int{}

func init() {
	idx := 0
	for _, g := range [][]string{
		{"ax", "rax", "eax", "ax", "al"}, {"bx", "rbx", "ebx", "bx", "bl"}, {"cx", "rcx", "ecx", "cx", "cl"}, {"dx", "rdx", "edx", "dx", "dl"},
		{"si", "rsi", "esi", "si", "sil"}, {"di", "rdi", "edi", "di", "dil"}, {"bp", "rbp", "ebp", "bp", "bpl"}, {"sp", "rsp", "esp", "sp", "spl"},
	} {
		for _, n := range g[1:] {
			usdtX86Regs[n] = g[0]
			usdtX86RegIndex[n] = idx
		}
		idx++
	}
	for i := 8; i <= 15; i++ {
		r := "r" + strconv.Itoa(i)
		for _, n := range []string{r, r + "d", r + "w", r + "b"} {
			usdtX86Regs[n] = r
			usdtX86RegIndex[n] = idx
		}
		idx++
	}
}

// Compiler USDT spec-map layout; see docs/requirements_format.md and Support/Usdt.h.
const (
	USDTSpecSize    = 192 // 12 arguments of 16 bytes each.
	USDTArgSpecSize = 16  // kind u8 at +0, reg u8 at +1, six zero bytes, off i64 at +8 (little endian).
	USDTKindNone    = 0
	USDTKindConst   = 1
	USDTKindReg     = 2
	USDTKindDeref   = 3
)

// USDTRegIndex returns the ABI register index for an x86_64 note name without %.
// Unknown names return ok=false.
func USDTRegIndex(name string) (int, bool) {
	i, ok := usdtX86RegIndex[name]
	return i, ok
}

// EncodeUSDTSpec encodes the note's space-separated argument descriptions into
// the 192-byte map value required by docs/requirements_format.md. Unsupported
// locations (SIB, %rip or unknown registers) and arguments beyond twelve retain
// kind zero. If a program reads them, usdtarg_unknown already blocks loading;
// locations of unread arguments do not affect program values. unread lists the
// one-based argument numbers left at kind zero for caller records.
func EncodeUSDTSpec(args string) (spec [USDTSpecSize]byte, unread []int) {
	for i, s := range strings.Fields(args) {
		if i >= USDTSpecSize/USDTArgSpecSize {
			unread = append(unread, i+1)
			continue
		}
		a, _, err := ParseUSDTArg(s)
		b := spec[i*USDTArgSpecSize : (i+1)*USDTArgSpecSize]
		if err != nil {
			unread = append(unread, i+1)
			continue
		}
		switch a.Kind {
		case "const":
			b[0] = USDTKindConst
		case "reg":
			b[0] = USDTKindReg
		case "deref":
			b[0] = USDTKindDeref
		}
		if a.Kind != "const" {
			r, _ := USDTRegIndex(a.Reg) // Accept only names recognized by ParseUSDTArg.
			b[1] = byte(r)
		}
		binary.LittleEndian.PutUint64(b[8:], uint64(a.Off))
	}
	return spec, unread
}

// ParseUSDTArg reads one x86_64 argument description. sizeOK permits size and sign
// matching even if the location is unreadable. Locations must be %reg, off(%reg)
// or $imm; SIB off(%base,%index,scale), unknown registers and spellings return err.
func ParseUSDTArg(s string) (spec USDTArgSpec, sizeOK bool, err error) {
	sz, loc, ok := strings.Cut(s, "@")
	if !ok {
		return spec, false, fmt.Errorf("argument %q has no <size>@ (an old note format)", s)
	}
	n, e := strconv.Atoi(sz)
	if e != nil || n == 0 {
		return spec, false, fmt.Errorf("argument %q has a size this check cannot read", s)
	}
	if n < 0 {
		spec.Signed, n = true, -n
	}
	if n != 1 && n != 2 && n != 4 && n != 8 {
		return spec, false, fmt.Errorf("argument %q has size %d (want 1, 2, 4 or 8)", s, n)
	}
	spec.Size = n
	reg := func(r string) (string, error) {
		if _, ok := usdtX86Regs[r]; !ok {
			return "", fmt.Errorf("argument %q names register %%%s, which the loader does not read (x86_64 general purpose registers only)", s, r)
		}
		return r, nil
	}
	switch {
	case strings.HasPrefix(loc, "%"):
		spec.Kind = "reg"
		spec.Reg, err = reg(loc[1:])
	case strings.HasPrefix(loc, "$"):
		spec.Kind = "const"
		if spec.Off, e = strconv.ParseInt(loc[1:], 0, 64); e != nil {
			err = fmt.Errorf("argument %q has a constant this check cannot read", s)
		}
	case strings.HasSuffix(loc, ")") && strings.Contains(loc, "(%"):
		off, inner, _ := strings.Cut(loc[:len(loc)-1], "(%")
		if strings.Contains(inner, ",") {
			return spec, true, fmt.Errorf("argument %q is a SIB memory operand (base, index, scale), which the loader does not read in v1", s)
		}
		spec.Kind = "deref"
		if off != "" {
			if spec.Off, e = strconv.ParseInt(off, 0, 64); e != nil {
				return spec, true, fmt.Errorf("argument %q has an offset this check cannot read", s)
			}
		}
		spec.Reg, err = reg(inner)
	default:
		err = fmt.Errorf("argument %q has a place this check cannot read", s)
	}
	return spec, true, err
}

// usdtTypeOf returns size and signedness for an usdtarg type spelling (i8 through u64).
func usdtTypeOf(t string) (size int, signed bool) {
	bits, _ := strconv.Atoi(t[1:])
	return bits / 8, t[0] == 'i'
}

// usdtSpelling spells size and sign: -4@ is i32; 8@ is u64.
func usdtSpelling(size int, signed bool) string {
	if signed {
		return "i" + strconv.Itoa(size*8)
	}
	return "u" + strconv.Itoa(size*8)
}

// checkUSDT matches arch, ctxfield registers, loader usdt_attach declaration,
// binary SHA-256, point and semaphore presence (usdt_probe), and argument count,
// size, signedness and location readability (usdtarg/usdtarg_unknown) at every pc.
// Keep Unmet Kind values as string literals: spec tests read the source.
// Programs with ebpf.usdt.arg have a __ebpf_usdt_spec_<program> map. Too many
// points for max_entries is usdt_probe: loaders store point i's spec at key i and
// attach with cookie i; an omitted point would silently yield st=-ENOENT.
func checkUSDT(req *Requirements, a Attach, caps Capabilities) ([]Unmet, error) {
	if a.USDTSem == "" {
		return nil, fmt.Errorf("program %s: usdt attach row without a usdtsem row", a.Program)
	}
	out, _, err := checkArchAndCtx(a, caps)
	if err != nil {
		return nil, err
	}
	// Loader declarations: none cannot attach; plain cannot pass ref_ctr_offset for
// semaphore points (which would silently produce no events); missing is Unknown.
	decl := loaderOf(caps)
	switch decl.USDTAttach {
	case USDTAttachNone:
		out = append(out, Unmet{Kind: "usdt_loader", Program: a.Program, Name: a.Target,
			Detail: fmt.Sprintf("the loader %q does not attach USDT points (usdt_attach none)", decl.Name)})
	case USDTAttachPlain:
		if a.USDTSem == "required" {
			out = append(out, Unmet{Kind: "usdt_loader", Program: a.Program, Name: a.Target,
				Detail: fmt.Sprintf("the points are guarded by a semaphore, but the loader %q cannot pass the uprobe ref_ctr_offset (usdt_attach plain) — the points would not fire and the program would see no events silently", decl.Name)})
		}
	case USDTAttachRefCtr:
	default:
		out = append(out, Unmet{Kind: "usdt_loader_unknown", Program: a.Program, Name: a.Target,
			Detail: fmt.Sprintf("the loader %q does not declare usdt_attach", decl.Name)})
	}
	f, out, err := openUprobeBinary(a, caps, out)
	if err != nil || f == nil {
		return out, err
	}
	points, err := ReadUSDTPoints(f)
	if err != nil {
		return append(out, Unmet{Kind: "usdtarg_unknown", Program: a.Program, Name: a.Target, Detail: "the binary's stapsdt notes cannot be read: " + err.Error()}), nil
	}
	provider, name, _ := strings.Cut(a.Target, ":")
	var mine []USDTPoint
	for _, p := range points {
		if p.Provider == provider && p.Name == name {
			mine = append(mine, p)
		}
	}
	if len(mine) == 0 {
		return append(out, Unmet{Kind: "usdt_probe", Program: a.Program, Name: a.Target,
			Detail: fmt.Sprintf("the binary has no stapsdt note for %s (%d points of other probes)", a.Target, len(points))}), nil
	}
	if req != nil {
		for _, m := range req.Maps {
			if m.Symbol == USDTSpecMapPrefix+a.Program && uint64(len(mine)) > m.MaxEntries {
				out = append(out, Unmet{Kind: "usdt_probe", Program: a.Program, Name: a.Target,
					Detail: fmt.Sprintf("the binary has %d points of %s, but the object's USDT spec map %s holds %d (max_points) — the points past it would read no spec", len(mine), a.Target, m.Symbol, m.MaxEntries)})
			}
		}
	}
	maxN := 0
	if l := len(a.USDTArgs); l > 0 {
		maxN = a.USDTArgs[l-1].N
	}
	for _, p := range mine {
		at := fmt.Sprintf("%s at pc 0x%x", a.Target, p.PC)
		if has := p.Semaphore != 0; has != (a.USDTSem == "required") {
			d := "has no semaphore, but the object declares the point semaphore-guarded (usdtsem required)"
			if has {
				d = fmt.Sprintf("has a semaphore (0x%x), but the object declares none (usdtsem none) — a loader that passes no ref_ctr_offset leaves the point silent", p.Semaphore)
			}
			out = append(out, Unmet{Kind: "usdt_probe", Program: a.Program, Name: at, Detail: "the point " + d})
		}
		args := strings.Fields(p.Args)
		if maxN > len(args) {
			out = append(out, Unmet{Kind: "usdtarg", Program: a.Program, Name: at,
				Detail: fmt.Sprintf("the point has %d arguments (%q), but the object reads argument %d", len(args), p.Args, maxN)})
			continue
		}
		for _, k := range a.USDTArgs {
			an := fmt.Sprintf("%d of %s at pc 0x%x (%s)", k.N, a.Target, p.PC, k.Type)
			spec, sizeOK, err := ParseUSDTArg(args[k.N-1])
			if !sizeOK {
				out = append(out, Unmet{Kind: "usdtarg_unknown", Program: a.Program, Name: an, Detail: err.Error()})
				continue
			}
			if size, signed := usdtTypeOf(k.Type); size != spec.Size || signed != spec.Signed {
				out = append(out, Unmet{Kind: "usdtarg", Program: a.Program, Name: an,
					Detail: fmt.Sprintf("argument %d of the point is %q (%s), but the object reads it as %s", k.N, args[k.N-1], usdtSpelling(spec.Size, spec.Signed), k.Type)})
				continue
			}
			if err != nil {
				out = append(out, Unmet{Kind: "usdtarg_unknown", Program: a.Program, Name: an, Detail: err.Error()})
			}
		}
	}
	return out, nil
}
