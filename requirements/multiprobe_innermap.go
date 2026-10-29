package requirements

import (
	"fmt"
	"strconv"
	"strings"
)

// Format 12 adds multi-probe targets, USDT companions (checked in usdt.go) and
// inner-map templates. See docs/requirements_format.md sections 3 and 4.
//
// multiCount parses the positive number of targets in a multi attach row.
func multiCount(s string) (int, bool) {
	n, err := strconv.Atoi(s)
	return n, err == nil && n >= 1
}

// validUSDTTarget requires <provider>:<name>, both C identifiers.
func validUSDTTarget(s string) bool {
	p, n, ok := strings.Cut(s, ":")
	return ok && validCName(p) && validCName(n)
}

// validSymbolName accepts nonempty ASCII without spaces/control characters,
// including kernel foo.isra.0, Go main.f and C++ mangled names.
func validSymbolName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return false
		}
	}
	return true
}

// isOfMaps identifies outer map types requiring an innermap template.
func isOfMaps(mapType string) bool { return mapType == "array_of_maps" || mapType == "hash_of_maps" }

// checkMultiAndInnerMapPending rejects an incomplete multi target list before leaving its
// companion rows, or a format-12 of_maps map not immediately followed by
// innermap. n == 0 marks end of input; row names the offending row kind.
func (r *Requirements) checkMultiAndInnerMapPending(n int, row, afterMap string) error {
	if k := len(r.Attaches) - 1; k >= 0 {
		a := r.Attaches[k]
		if isMultiAttachType(a.AttachType) && len(a.MTargets) < a.MultiN {
			switch row {
			case "arch", "ctxfield", "binary", "mtarget":
			default:
				if n == 0 {
					return perr(0, "mtarget", RuleOrder, "%s: %s attach of %s declares %d functions but has %d mtarget rows", Section, a.AttachType, a.Program, a.MultiN, len(a.MTargets))
				}
				return perr(n, row, RuleOrder, "%s line %d: %s row before the %d mtarget rows of the %s attach of %s are complete (%d so far)", Section, n, row, a.MultiN, a.AttachType, a.Program, len(a.MTargets))
			}
		}
	}
	if afterMap != "" && r.Version >= MultiAndInnerMapMinVersion && row != "innermap" {
		for _, m := range r.Maps {
			if m.Symbol == afterMap && isOfMaps(m.MapType) {
				if n == 0 {
					return perr(0, "innermap", RuleOrder, "%s: map %s (%s) needs an innermap row right after it (version %d)", Section, m.Symbol, m.MapType, MultiAndInnerMapMinVersion)
				}
				return perr(n, row, RuleOrder, "%s line %d: map %s (%s) needs an innermap row right after it (version %d), got a %s row", Section, n, m.Symbol, m.MapType, MultiAndInnerMapMinVersion, row)
			}
		}
	}
	return nil
}

// parseMultiAndInnerMapCompanion enforces multi arch -> ctxfield (-> binary) -> exactly N
// mtarget rows with contiguous indices from zero -> argument rows. USDT uses
// arch -> ctxfield -> binary -> one usdtsem -> strictly increasing usdtarg
// indices in 1..12.
func (r *Requirements) parseMultiAndInnerMapCompanion(n int, f []string, line string) error {
	k := len(r.Attaches) - 1
	outOfOrder := func() error {
		return perr(n, f[0], RuleOrder, "%s line %d: %s row out of order %q", Section, n, f[0], line)
	}
	bad := func() error { return perr(n, f[0], RuleValue, "%s line %d: bad %s row %q", Section, n, f[0], line) }
	if k < 0 || r.Attaches[k].Program != f[1] {
		return outOfOrder()
	}
	a := &r.Attaches[k]
	switch f[0] {
	case "mtarget":
		if !isMultiAttachType(a.AttachType) || a.Arch == "" || (isUprobeFamily(a.AttachType) && a.BinarySHA256 == "") || len(a.KprobeArgs) > 0 || len(a.UprobeArgs) > 0 {
			return outOfOrder()
		}
		idx, err := strconv.Atoi(f[2])
		if err != nil || idx < 0 || !validSymbolName(f[3]) {
			return bad()
		}
		if idx != len(a.MTargets) {
			return outOfOrder()
		}
		if idx >= a.MultiN {
			return perr(n, f[0], RuleValue, "%s line %d: mtarget index %d is not below the function count %d of the attach row %q", Section, n, idx, a.MultiN, line)
		}
		a.MTargets = append(a.MTargets, f[3])
	case "usdtsem":
		if a.AttachType != "usdt" || a.BinarySHA256 == "" || a.USDTSem != "" {
			return outOfOrder()
		}
		if f[2] != "required" && f[2] != "none" {
			return bad()
		}
		a.USDTSem = f[2]
	case "usdtarg":
		if a.AttachType != "usdt" || a.USDTSem == "" {
			return outOfOrder()
		}
		na, err := strconv.Atoi(f[2])
		if err != nil || na < 1 || na > USDTMaxArgs || !validIntSpelling(f[3]) {
			return bad()
		}
		if l := len(a.USDTArgs); l > 0 && na <= a.USDTArgs[l-1].N {
			return outOfOrder()
		}
		a.USDTArgs = append(a.USDTArgs, KprobeArg{na, f[3]})
	}
	return nil
}

// USDTMaxArgs matches the libbpf spec's args[12] bound.
const USDTMaxArgs = 12

// parseInnerMap requires an innermap immediately after the same symbol's
// array_of_maps/hash_of_maps row, using map field spellings. Nested map-in-map
// templates are invalid, as the kernel's bpf_map_meta_alloc rejects them.
func (r *Requirements) parseInnerMap(n int, f []string, line, afterMap string) error {
	var outer *Map
	for i := range r.Maps {
		if r.Maps[i].Symbol == afterMap {
			outer = &r.Maps[i]
		}
	}
	if afterMap == "" || outer == nil || f[1] != afterMap || !isOfMaps(outer.MapType) {
		return perr(n, f[0], RuleOrder, "%s line %d: innermap row is not right after its array_of_maps / hash_of_maps map row %q", Section, n, line)
	}
	id, err1 := strconv.ParseInt(f[3], 10, 64)
	maxE, err2 := strconv.ParseUint(f[6], 10, 64)
	flags, err3 := strconv.ParseUint(f[7], 10, 64)
	if err1 != nil || err2 != nil || err3 != nil || !validAttachTypeName(f[2]) || isOfMaps(f[2]) || f[4] == "" || f[5] == "" {
		return perr(n, f[0], RuleValue, "%s line %d: bad innermap row %q", Section, n, line)
	}
	r.InnerMaps = append(r.InnerMaps, InnerMap{Outer: f[1], MapType: f[2], ID: id, Key: f[4], Value: f[5], MaxEntries: maxE, Flags: flags})
	return nil
}

// InnerMapSpelling encodes kind=<type> key=<key> value=<value> max_entries=<N>
// flags=<F> for CheckShared and section 12 inner declared/elf problems.
func InnerMapSpelling(m InnerMap) string {
	return fmt.Sprintf("kind=%s key=%s value=%s max_entries=%d flags=%d", m.MapType, m.Key, m.Value, m.MaxEntries, m.Flags)
}

// multiAttachType returns trace_kprobe_multi or trace_uprobe_multi UAPI names.
func multiAttachType(t string) string {
	if t == "kprobe_multi" || t == "kretprobe_multi" {
		return "trace_kprobe_multi"
	}
	return "trace_uprobe_multi"
}

// checkMulti checks attach type, architecture and context as the single family
// does, then each mtarget. Kernel probes check kallsyms and FUNC_PROTO args;
// attach_alias is never queried because cilium/libbpf multi does not retry an
// alias. User probes check the shared binary, symbols, DWARF args and ABI.
// Unmet Name identifies the target; no extra Unmet kinds are introduced.
func checkMulti(req *Requirements, a Attach, caps Capabilities, asked map[string]bool) ([]Unmet, error) {
	if len(a.MTargets) != a.MultiN {
		return nil, fmt.Errorf("program %s: %s attach row with %d mtarget rows, want %d", a.Program, a.AttachType, len(a.MTargets), a.MultiN)
	}
	out, err := checkAttachType(req, a.Program, multiAttachType(a.AttachType), caps, asked)
	if err != nil {
		return nil, err
	}
	u, targetArch, err := checkArchAndCtx(a, caps)
	if err != nil {
		return nil, err
	}
	out = append(out, u...)
	if a.AttachType == "kprobe_multi" || a.AttachType == "kretprobe_multi" {
		for i, t := range a.MTargets {
			b := a
			b.Target = t
			if len(a.MTargetArgs) > 0 { // Per-target mtargetarg rows are mutually exclusive with kprobearg.
				b.KprobeArgs = mtargetArgsOf(a, i)
			}
			if out, err = checkKprobeTarget(b, caps, out, targetArch, false); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	b := a
	b.Target = strings.Join(a.MTargets, ",") // Binary Unmet Name identifies the target list.
	f, out, err := openUprobeBinary(b, caps, out)
	if err != nil || f == nil {
		return out, err
	}
	source := &uprobeDWARFSource{body: f, caps: caps, program: a.Program}
	for i, t := range a.MTargets {
		c := a
		if len(a.MTargetArgs) > 0 { // Per-target mtargetarg rows are mutually exclusive with uprobearg.
			c.UprobeArgs = mtargetArgsOf(a, i)
		}
		out = append(out, uprobeTargetUnmets(f, c, t, a.AttachType == "uretprobe_multi", source)...)
	}
	return out, nil
}
