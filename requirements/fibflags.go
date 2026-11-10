package requirements

import (
	"errors"
	"fmt"
	"strconv"
)

// bpf_fib_lookup flag masks. A fibflags row is
// fibflags <program> <none|direct> <mask> (format 21, specification section 3).
// Whether the target's bpf_fib_lookup accepts the mask for the program type is
// a live fact (query fib_lookup_flags); false and Unknown both block the load.

// FibFlagsMinVersion is the first format that can contain fibflags rows.
const FibFlagsMinVersion = 21

// QueryFibLookupFlags asks whether bpf_fib_lookup accepts a flag mask for a
// program type (a load probe — privilege-dependent).
const QueryFibLookupFlags = "fib_lookup_flags"

// FibFlagMasks maps the compiler's flag names to their masks: none is 0 and
// direct is the UAPI BPF_FIB_LOOKUP_DIRECT value (a test checks abi/uapi.tsv
// fibflag rows).
var FibFlagMasks = map[string]uint32{"none": 0, "direct": 1}

// FibFlag is one fibflags row.
type FibFlag struct {
	Program, Name string
	Mask          uint32
}

// FibLookupFlagsCaps answers whether bpf_fib_lookup accepts mask for the
// program type (name and UAPI ID). Callers pass the ELF's program type as-is;
// implementations answer Unknown for anything they cannot match exactly.
type FibLookupFlagsCaps interface {
	HasFibLookupFlags(progType string, progTypeID int64, mask uint32) (bool, error)
}

// FibLookupFlagsKey is the recorded-caps key <program type>/<ID>/<mask>.
func FibLookupFlagsKey(progType string, progTypeID int64, mask uint32) string {
	return progType + "/" + strconv.FormatInt(progTypeID, 10) + "/" + strconv.FormatUint(uint64(mask), 10)
}

// parseFibFlags reads a fibflags row: the program must be declared, the name
// known and its mask equal to the table's, rows in program order then strictly
// increasing mask (no duplicates).
func (r *Requirements) parseFibFlags(n int, f []string, line string, byName map[string]int) error {
	idx, ok := byName[f[1]]
	if !ok {
		return perr(n, f[0], RuleOrder, "%s line %d: fibflags for unknown program %q", Section, n, f[1])
	}
	want, known := FibFlagMasks[f[2]]
	mask, err := strconv.ParseUint(f[3], 10, 32)
	if !known || err != nil || uint32(mask) != want {
		return perr(n, f[0], RuleValue, "%s line %d: bad fibflags row %q (flag none = 0 or direct = %d, the mask must match the name)", Section, n, line, FibFlagMasks["direct"])
	}
	if k := len(r.FibFlags); k > 0 {
		prev := r.FibFlags[k-1]
		pi := byName[prev.Program]
		if pi > idx || (pi == idx && prev.Mask >= uint32(mask)) {
			return perr(n, f[0], RuleOrder, "%s line %d: fibflags row out of order or repeated %q (program order, then increasing mask)", Section, n, line)
		}
	}
	r.FibFlags = append(r.FibFlags, FibFlag{Program: f[1], Name: f[2], Mask: uint32(mask)})
	return nil
}

// checkFibFlags asks fib_lookup_flags for each row with the ELF's program type
// name and ID. No query, Unknown (including a privilege mismatch) and false all
// block: a rejected mask returns -EINVAL from the helper at run time, which the
// verifier does not see.
func checkFibFlags(req *Requirements, caps Capabilities) ([]Unmet, error) {
	var out []Unmet
	fc, ok := capsAs[FibLookupFlagsCaps](caps, QueryFibLookupFlags)
	for _, ff := range req.FibFlags {
		name := fmt.Sprintf("%s (mask %d)", ff.Name, ff.Mask)
		if !ok {
			out = append(out, Unmet{Kind: "fibflags_unknown", Program: ff.Program, Name: name, Detail: "no fib_lookup_flags probe"})
			continue
		}
		p, found := programOf(req, ff.Program)
		if !found {
			return nil, fmt.Errorf("fibflags for unknown program %s", ff.Program)
		}
		has, err := fc.HasFibLookupFlags(p.ProgType, p.ProgTypeID, ff.Mask)
		switch {
		case errors.Is(err, ErrUnknown):
			out = append(out, Unmet{Kind: "fibflags_unknown", Program: ff.Program, Name: name, Detail: err.Error()})
		case err != nil:
			return nil, err
		case !has:
			out = append(out, Unmet{Kind: "fibflags", Program: ff.Program, Name: name, Detail: p.ProgType})
		}
	}
	return out, nil
}
