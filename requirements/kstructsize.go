package requirements

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Format 28 adds kstructsize <struct> <N>: an embedded kernel struct of
// N bytes in a map value or global (today only bpf_cpumask — ebpf.ref.field.addr
// passes its address to the cpumask kfuncs, which write the target kernel's
// sizeof(struct bpf_cpumask) bytes there). The loader checks every row: a
// target struct larger than any N would overwrite the bytes after the field.
// See docs/requirements_format.md sections 3, 5 and 6.
const KStructSizeMinVersion = 28

// KStructSizeStructs is the closed set of struct names a kstructsize row may
// name. Adding a name is a format bump.
var KStructSizeStructs = map[string]bool{"bpf_cpumask": true}

// KStructSize is kstructsize <struct> <N>.
type KStructSize struct {
	Struct string
	Size   uint32
}

// ErrKStructAbsent marks a struct the target BTF does not have. It is a known
// answer (Unmet kstructsize), not ErrUnknown.
var ErrKStructAbsent = errors.New("struct absent")

// KernelStructSizes answers kstruct_size: the byte size of the named STRUCT in
// the target vmlinux BTF. Absence wraps ErrKStructAbsent; unreadable BTF, a
// module-only or duplicated struct wraps ErrUnknown; other errors (a non-STRUCT
// type, a size over u32) are checking errors.
type KernelStructSizes interface {
	StructSize(name string) (uint32, error)
}

// KStructSizeKey encodes <struct> for recorded kstruct_size (section 10).
func KStructSizeKey(name string) string { return name }

// FormatKStructSize spells a size as in recorded answers (0x and 8 lowercase
// hexadecimal digits — the enum_values form at 32 bits).
func FormatKStructSize(v uint32) string { return fmt.Sprintf("0x%08x", v) }

func parseKStructSizeAnswer(s string) (uint32, bool) {
	h, ok := strings.CutPrefix(s, "0x")
	if !ok || len(h) != 8 || strings.ToLower(h) != h {
		return 0, false
	}
	v, err := strconv.ParseUint(h, 16, 32)
	return uint32(v), err == nil
}

// parseKStructSize parses a kstructsize row. N is a positive decimal multiple
// of 8 without leading zeros; rows sort by N ascending without repeats.
func (r *Requirements) parseKStructSize(n int, f []string, line string) error {
	if !KStructSizeStructs[f[1]] {
		return perr(n, f[0], RuleValue, "%s line %d: kstructsize names unknown struct %q", Section, n, f[1])
	}
	v, err := strconv.ParseUint(f[2], 10, 32)
	if err != nil || v == 0 || v%8 != 0 || strconv.FormatUint(v, 10) != f[2] {
		return perr(n, f[0], RuleValue, "%s line %d: bad kstructsize row %q (the size is a positive decimal multiple of 8)", Section, n, line)
	}
	if l := len(r.KStructSizes); l > 0 {
		p := r.KStructSizes[l-1]
		if f[1] < p.Struct || (f[1] == p.Struct && uint32(v) <= p.Size) {
			return perr(n, f[0], RuleOrder, "%s line %d: kstructsize row out of order or repeated %q", Section, n, line)
		}
	}
	r.KStructSizes = append(r.KStructSizes, KStructSize{Struct: f[1], Size: uint32(v)})
	return nil
}

// checkKStructSizes checks every kstructsize row (not only the largest or the
// last — the smallest N is the one a larger target struct overruns). A larger
// target struct or an absent one is kstructsize; no query or an unknown answer
// is kstructsize_unknown. Both block. Keep Unmet Kind as literals for
// spec_test's source/table comparison.
func checkKStructSizes(req *Requirements, caps Capabilities) ([]Unmet, error) {
	var out []Unmet
	kc, ok := capsAs[KernelStructSizes](caps, QueryKStructSize)
	for _, k := range req.KStructSizes {
		name := k.Struct + "/" + strconv.FormatUint(uint64(k.Size), 10)
		if !ok {
			out = append(out, Unmet{Kind: "kstructsize_unknown", Name: name, Detail: "no struct size probe"})
			continue
		}
		got, err := kc.StructSize(k.Struct)
		switch {
		case errors.Is(err, ErrUnknown):
			out = append(out, Unmet{Kind: "kstructsize_unknown", Name: name, Detail: err.Error()})
		case errors.Is(err, ErrKStructAbsent):
			out = append(out, Unmet{Kind: "kstructsize", Name: name,
				Detail: fmt.Sprintf("%v (the object embeds %d bytes)", err, k.Size)})
		case err != nil:
			return nil, err
		case got > k.Size:
			out = append(out, Unmet{Kind: "kstructsize", Name: name,
				Detail: fmt.Sprintf("the target's struct %s is %d bytes, the object embeds %d", k.Struct, got, k.Size)})
		}
	}
	return out, nil
}

// kstructName / kstructBytes split an Unmet Name "<struct>/<N>".
func kstructName(n string) string  { s, _, _ := strings.Cut(n, "/"); return s }
func kstructBytes(n string) string { _, b, _ := strings.Cut(n, "/"); return b }

// StructSize key: <struct>. A text answer is the size; a diffs answer records
// absence (its text).
func (c *RecordedCaps) StructSize(name string) (uint32, error) {
	a, err := c.answer(QueryKStructSize, KStructSizeKey(name))
	if err != nil {
		return 0, err
	}
	if a.Diffs != nil {
		return 0, fmt.Errorf("%s: %w", strings.Join(*a.Diffs, "; "), ErrKStructAbsent)
	}
	if a.Text == nil {
		return 0, fmt.Errorf("recorded caps: %s %q is not a text or diffs answer", QueryKStructSize, KStructSizeKey(name))
	}
	v, ok := parseKStructSizeAnswer(*a.Text)
	if !ok {
		return 0, fmt.Errorf("recorded caps: %s %q: size %q is not 0x and 8 lowercase hexadecimal digits", QueryKStructSize, KStructSizeKey(name), *a.Text)
	}
	return v, nil
}

// StructSize forwards an available query (capsAs checks HasQuery first) and
// records the size as text, absence as diffs, Unknown and errors as such.
func (r *Recorder) StructSize(name string) (uint32, error) {
	v, err := r.under.(KernelStructSizes).StructSize(name)
	key := KStructSizeKey(name)
	switch {
	case errors.Is(err, ErrUnknown):
		r.put(QueryKStructSize, key, Answer{Unknown: err.Error()})
	case errors.Is(err, ErrKStructAbsent):
		// The sentinel suffix is added back on read, so a round trip keeps the text.
		d := []string{strings.TrimSuffix(err.Error(), ": "+ErrKStructAbsent.Error())}
		r.put(QueryKStructSize, key, Answer{Diffs: &d})
	case err != nil:
		r.put(QueryKStructSize, key, Answer{Error: err.Error()})
	default:
		s := FormatKStructSize(v)
		r.put(QueryKStructSize, key, Answer{Text: &s})
	}
	return v, err
}
