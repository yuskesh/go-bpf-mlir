package bindgen

import (
	"bytes"
	"fmt"
	"sort"
	"strings"
)

func emitRecordTypes(b *bytes.Buffer, s schema, sizes map[string]uint64) error {
	// --- record structs + decoders ---
	recs := append([]record(nil), s.Core.Records...)
	recByName := map[string]record{}
	for _, r := range s.Core.Records {
		recByName[r.Symbol] = r
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].Symbol < recs[j].Symbol })
	for _, r := range recs {
		name := exported(r.Symbol)
		fmt.Fprintf(b, "\n// %s is schema record %q (size=%d", name, r.Symbol, r.Size)
		if r.MinSize != r.Size {
			fmt.Fprintf(b, ", variable length, min=%d", r.MinSize)
		}
		b.WriteString(").\n")
		if r.Note != "" {
			fmt.Fprintf(b, "// %s\n", r.Note)
		}
		fmt.Fprintf(b, "type %s struct {\n", name)

		fields := append([]field(nil), r.Fields...)
		sort.Slice(fields, func(i, j int) bool { return fields[i].Offset < fields[j].Offset })
		// Go naturally aligns fields. Reject schema offsets not divisible by the Go
		// field alignment, or record sizes not divisible by struct alignment: Go would
		// insert padding and disagree. Reject here rather than defer to CheckLayout.
		for _, f := range fields {
			fa, err := goAlign(f.Type, recByName)
			if err != nil {
				return fmt.Errorf("record %q field %q: %w", r.Symbol, f.Name, err)
			}
			if f.Offset%fa != 0 {
				return fmt.Errorf("record %q field %q: offset %d is not a multiple of Go type alignment %d — not representable by a Go struct (unsupported by bindgen)", r.Symbol, f.Name, f.Offset, fa)
			}
		}
		if ra, err := recordAlign(r, recByName); err != nil {
			return err
		} else if r.Size%ra != 0 {
			return fmt.Errorf("record %q: size %d is not a multiple of Go struct alignment %d — Go would add tail padding (unsupported by bindgen)", r.Symbol, r.Size, ra)
		}
		var at uint64
		// Padding must use blank (_) fields. Nonblank unexported names such as _pad0
		// make encoding/binary panic when cilium Map.Lookup unmarshals into them.
		// Blank fields are skipped when reading and written as zero.
		for _, f := range fields {
			if f.Offset > at {
				fmt.Fprintf(b, "\t_ [%d]byte // schema-declared padding, independent of Go layout\n", f.Offset-at)
				at = f.Offset
			}
			// spin_lock/timer are inaccessible tagged blank fields; layout.Check matches BTF members exactly.
			if btfName, ok := opaqueFields[f.Type.Kind]; ok {
				n := opaqueSizes[f.Type.Kind]
				fmt.Fprintf(b, "\t_ [%d]byte `schema:%q opaque:%q` // %s — inaccessible to userspace (kernel lookup returns zero; the kernel ignores these bytes on writes)", n, f.Name, btfName, btfName)
				if f.Type.Kind == "timer" {
					b.WriteString(". **Updating this element from userspace stops an active timer** (measured on three kernels)")
				} else {
					b.WriteString(". A userspace update without the flag does not take the lock (measured)")
				}
				b.WriteString("\n")
				at = f.Offset + n
				continue
			}
			// Embedded cpumasks are inaccessible holes; layout.Check matches the BTF member's
			// __ebpf_cpumask_<N> STRUCT of N bytes.
			if f.Type.Kind == "cpumask" {
				fmt.Fprintf(b, "\t_ [%d]byte `schema:%q opaque:%q` // embedded struct bpf_cpumask — inaccessible to userspace (written in place by the cpumask kfuncs; "+
					"the loader checks the target's struct size against these %d bytes — kstructsize)\n", f.Type.Size, f.Name, cpumaskOpaque, f.Type.Size)
				at = f.Offset + f.Type.Size
				continue
			}
			// Referenced kptr values are inaccessible holes; layout.Check matches PTR -> TYPE_TAG kptr -> STRUCT.
			if f.Type.Kind == "kptr" {
				fmt.Fprintf(b, "\t_ [%d]byte `schema:%q opaque:%q` // kptr (reference to struct %s) — inaccessible to userspace (kernel lookup returns zero; "+
					"on userspace update or deletion, the kernel releases the stored reference through its dtor)\n", kptrHoleSize, f.Name, kptrOpaque, f.Type.Struct)
				at = f.Offset + kptrHoleSize
				continue
			}
			gt, sz, err := goType(f.Type, sizes)
			if err != nil {
				return fmt.Errorf("record %q field %q: %w", r.Symbol, f.Name, err)
			}
			// Tags carry schema field names for layout.Check to match BTF members.
			// Nested records also carry a record tag for nominal BTF struct-name matching.
			if f.Type.Kind == "record_ref" {
				fmt.Fprintf(b, "\t%s %s `schema:%q record:%q`", exported(f.Name), gt, f.Name, f.Type.Symbol)
			} else if rec := innerRecord(f.Type); rec != "" {
				// Record arrays carry the element record name for layout.Check's nominal BTF check.
				fmt.Fprintf(b, "\t%s %s `schema:%q record:%q`", exported(f.Name), gt, f.Name, rec)
			} else {
				fmt.Fprintf(b, "\t%s %s `schema:%q`", exported(f.Name), gt, f.Name)
			}
			if f.Note != "" {
				fmt.Fprintf(b, " // %s", strings.ReplaceAll(f.Note, "\n", " "))
			}
			b.WriteString("\n")
			at = f.Offset + sz
		}
		if r.Size > at {
			fmt.Fprintf(b, "\t_ [%d]byte // tail padding\n", r.Size-at)
		}
		b.WriteString("}\n")

		fmt.Fprintf(b, "\n// Size%s is the schema-declared record size.\nconst Size%s = %d\n",
			name, name, r.Size)

		// Schema expose=str generates a convenience method reading through the first NUL.
		for _, f := range fields {
			if f.Expose != "str" || f.Type.Kind != "array" || f.Type.Element == nil ||
				f.Type.Element.Bits != 8 {
				continue
			}
			fn := exported(f.Name)
			fmt.Fprintf(b, `
// %sString reads %s as a NUL-terminated string (schema expose = "str").
func (v *%s) %sString() string {
	buf := make([]byte, 0, %d)
	for _, c := range v.%s {
		if c == 0 {
			break
		}
		buf = append(buf, byte(c))
	}
	return string(buf)
}
`, fn, f.Name, name, fn, f.Type.Count, fn)
		}

		// Decode by offsets, independently of Go struct layout.
		fmt.Fprintf(b, `
// Decode reads raw ring-buffer bytes. **Offsets follow the schema declarations**;
// reading does not depend on Go struct layout.
func (v *%s) Decode(b []byte) error {
	if len(b) < %d {
		return fmt.Errorf("%s: %%d bytes available (need at least %d bytes)", len(b))
	}
`, name, r.MinSize, r.Symbol, r.MinSize)
		for _, f := range fields {
			if err := emitDecode(b, f, sizes, r); err != nil {
				return err
			}
		}
		b.WriteString("\treturn nil\n}\n")
	}

	return nil
}
