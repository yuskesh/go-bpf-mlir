package requirements

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// HelperTargetMinVersion adds a target-specific typed helper dependency.
const HelperTargetMinVersion = 31

// QueryHelperTarget records a well-typed load probe at the actual attach target.
const QueryHelperTarget = "helper_target"

// HelperTarget binds a helper call to its program, attach target and typed arg.
// The initial subset is d_path(147), tracing/fentry, argument 0: struct path*.
type HelperTarget struct {
	Program, Helper, AttachType, Target, ArgType string
	HelperID                                     int64
	ArgIndex                                     int
}

// TargetHelperCaps is separate from the generic Tracing helper prototype probe.
// Empty diffs mean a well-typed load succeeded at the actual target; ErrUnknown
// is indeterminate, other errors are query failures. All prevent a silent fallback.
type TargetHelperCaps interface {
	CheckHelperTarget(progType string, progTypeID int64, target HelperTarget) ([]string, error)
}

func validHelperTargetSymbol(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if c == '_' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' {
			continue
		}
		if i > 0 && (c == '.' || c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func validHelperTarget(h HelperTarget) bool {
	return h.Helper == "d_path" && h.HelperID == 147 && h.AttachType == "trace_fentry" &&
		h.ArgIndex == 0 && h.ArgType == "path" && validHelperTargetSymbol(h.Target)
}

// HelperTargetKey includes every kernel query input, excluding the program's
// object-local name. Canonical JSON prevents delimiter aliases in target names.
func HelperTargetKey(pt string, id int64, h HelperTarget) string {
	b, _ := json.Marshal([]string{pt, strconv.FormatInt(id, 10), h.AttachType, h.Target,
		h.Helper, strconv.FormatInt(h.HelperID, 10), strconv.Itoa(h.ArgIndex), h.ArgType})
	return string(b)
}

func parseHelperTargetKey(key string) (string, int64, HelperTarget, error) {
	var f []string
	if err := json.Unmarshal([]byte(key), &f); err != nil || len(f) != 8 {
		return "", 0, HelperTarget{}, fmt.Errorf("helper_target: key must be a canonical eight-string JSON array")
	}
	id, e1 := strconv.ParseInt(f[1], 10, 64)
	hid, e2 := strconv.ParseInt(f[5], 10, 64)
	arg, e3 := strconv.Atoi(f[6])
	h := HelperTarget{Helper: f[4], HelperID: hid, AttachType: f[2], Target: f[3], ArgIndex: arg, ArgType: f[7]}
	if e1 != nil || e2 != nil || e3 != nil || f[0] != "tracing" || id != 26 ||
		!validHelperTarget(h) || HelperTargetKey(f[0], id, h) != key {
		return "", 0, HelperTarget{}, fmt.Errorf("helper_target: noncanonical or unsupported key %q", key)
	}
	return f[0], id, h, nil
}

func helperTargetOrder(h HelperTarget) string {
	return h.Program + "\x00" + strconv.FormatInt(h.HelperID, 10) + "\x00" + h.AttachType + "\x00" + h.Target + "\x00" + strconv.Itoa(h.ArgIndex) + "\x00" + h.ArgType
}

func (r *Requirements) helperTargetBound(h HelperTarget) bool {
	present := false
	for _, p := range r.Programs {
		if p.Symbol != h.Program || p.ProgType != "tracing" || p.ProgTypeID != 26 {
			continue
		}
		for _, helper := range p.Helpers {
			if helper.Name == h.Helper && helper.ID == h.HelperID {
				present = true
			}
		}
	}
	if !present {
		return false
	}
	for _, a := range r.Attaches {
		if a.Program == h.Program && a.AttachType == h.AttachType && a.Target == h.Target &&
			len(a.FArgs) > h.ArgIndex && a.FArgs[h.ArgIndex] == h.ArgType {
			return true
		}
	}
	return false
}

func (r *Requirements) parseHelperTarget(n int, f []string, line string) error {
	hid, e1 := strconv.ParseInt(f[3], 10, 64)
	arg, e2 := strconv.Atoi(f[6])
	h := HelperTarget{Program: f[1], Helper: f[2], HelperID: hid, AttachType: f[4], Target: f[5], ArgIndex: arg, ArgType: f[7]}
	if e1 != nil || e2 != nil || strconv.FormatInt(hid, 10) != f[3] || strconv.Itoa(arg) != f[6] || !validHelperTarget(h) {
		return perr(n, f[0], RuleValue, "%s line %d: unsupported helper_target row %q", Section, n, line)
	}
	if !r.helperTargetBound(h) {
		return perr(n, f[0], RuleDocument, "%s line %d: helper_target is not bound to preceding program/helper/attach/farg rows", Section, n)
	}
	if l := len(r.HelperTargets); l > 0 && helperTargetOrder(r.HelperTargets[l-1]) >= helperTargetOrder(h) {
		return perr(n, f[0], RuleOrder, "%s line %d: helper_target out of order or repeated", Section, n)
	}
	r.HelperTargets = append(r.HelperTargets, h)
	return nil
}

func needsHelperTarget(p Program, h Helper) bool {
	return (p.ProgType == "tracing" || p.ProgTypeID == 26) && (h.ID == 147 || h.Name == "d_path")
}

// checkHelperTargets deliberately closes the entire query population before
// returning any ordinary error. It runs before generic helper checks so a
// generic probe cannot short-circuit, contradict or replace this target probe.
func checkHelperTargets(req *Requirements, caps Capabilities) ([]Unmet, error) {
	var out []Unmet
	var errs []error
	query, have := capsAs[TargetHelperCaps](caps, QueryHelperTarget)
	for _, p := range req.Programs {
		for _, h := range p.Helpers {
			if !needsHelperTarget(p, h) {
				continue
			}
			bound := false
			for _, target := range req.HelperTargets {
				if target.Program == p.Symbol && target.Helper == h.Name && target.HelperID == h.ID && req.helperTargetBound(target) {
					bound = true
				}
			}
			if !bound {
				out = append(out, Unmet{Kind: "helper_target_unknown", Program: p.Symbol, Name: h.Name, ID: h.ID, Detail: "missing bound helper_target companion"})
			}
		}
	}
	for _, h := range req.HelperTargets {
		u := Unmet{Kind: "helper_target", Program: h.Program, Name: h.Helper, ID: h.HelperID}
		prefix := h.AttachType + "/" + h.Target + " arg" + strconv.Itoa(h.ArgIndex) + ":" + h.ArgType + ": "
		if !validHelperTarget(h) || !req.helperTargetBound(h) {
			u.Kind = "helper_target"
			u.Detail = prefix + "invalid binding"
			out = append(out, u)
			continue
		}
		if !have {
			u.Kind = "helper_target_unknown"
			u.Detail = prefix + "no target-specific helper probe"
			out = append(out, u)
			continue
		}
		d, err := query.CheckHelperTarget("tracing", 26, h)
		switch {
		case errors.Is(err, ErrUnknown):
			u.Kind = "helper_target_unknown"
			u.Detail = prefix + err.Error()
			out = append(out, u)
		case err != nil:
			errs = append(errs, fmt.Errorf("helper_target %s/%s: %w", h.Program, h.Target, err))
		case len(d) > 0:
			u.Kind = "helper_target"
			u.Detail = prefix + strings.Join(d, "; ")
			out = append(out, u)
		}
	}
	return out, errors.Join(errs...)
}

func (r *Recorder) CheckHelperTarget(pt string, id int64, h HelperTarget) ([]string, error) {
	d, err := r.under.(TargetHelperCaps).CheckHelperTarget(pt, id, h)
	return r.recDiffs(QueryHelperTarget, HelperTargetKey(pt, id, h), d, err)
}

func (c *RecordedCaps) helperTargetPrivilege() (Capabilities, error, bool) {
	// This typed load probe binds UID as well as CapEff. Older queries retain
	// their established capability-only ForLoad semantics.
	if c.scope != nil && c.ProbedAs != nil && c.ProbedAs.UID != c.scope.loadAs.UID {
		if c.scope.reprobe != nil {
			return c.scope.reprobe, nil, false
		}
		return nil, fmt.Errorf("recorded helper_target UID %d differs from load UID %d: %w", c.ProbedAs.UID, c.scope.loadAs.UID, ErrUnknown), false
	}
	return c.privileged(QueryHelperTarget)
}

func (c *RecordedCaps) CheckHelperTarget(pt string, id int64, h HelperTarget) ([]string, error) {
	if r, err, use := c.helperTargetPrivilege(); !use {
		if err != nil {
			return nil, err
		}
		q, ok := capsAs[TargetHelperCaps](r, QueryHelperTarget)
		if !ok {
			return nil, noReprobe(QueryHelperTarget)
		}
		return q.CheckHelperTarget(pt, id, h)
	}
	key := HelperTargetKey(pt, id, h)
	if _, ok := c.Queries[QueryHelperTarget][key]; !ok {
		return nil, fmt.Errorf("recorded caps: no answer for %s %q: %w", QueryHelperTarget, key, ErrUnknown)
	}
	return c.diffs(QueryHelperTarget, key)
}

func checkRecordedHelperTargets(c *RecordedCaps, data []byte) error {
	// Answer's legacy omitempty fields cannot distinguish an absent reason from
	// an explicitly empty one. This new query forbids both forms being present,
	// even if an empty reason would disappear from the legacy one-of count.
	var raw struct {
		Queries    map[string]map[string]json.RawMessage `json:"queries"`
		Privileged map[string]map[string]json.RawMessage `json:"privileged_queries"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	for _, queries := range []map[string]map[string]json.RawMessage{raw.Queries, raw.Privileged} {
		keys := make([]string, 0, len(queries[QueryHelperTarget]))
		for key := range queries[QueryHelperTarget] {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			answer := queries[QueryHelperTarget][key]
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(answer, &fields); err != nil {
				return err
			}
			if len(fields) != 1 {
				return fmt.Errorf("caps: helper_target %q needs exactly one answer field", key)
			}
			for name, value := range fields {
				switch name {
				case "diffs":
					var d []string
					if err := json.Unmarshal(value, &d); err != nil || d == nil {
						return fmt.Errorf("caps: helper_target %q needs a non-null diffs array", key)
					}
				case "unknown", "error":
					var reason string
					if err := json.Unmarshal(value, &reason); err != nil || strings.TrimSpace(reason) == "" {
						return fmt.Errorf("caps: helper_target %q needs a nonempty %s reason", key, name)
					}
				default:
					return fmt.Errorf("caps: helper_target %q does not accept answer %q", key, name)
				}
			}
		}
	}
	for _, queries := range []map[string]map[string]Answer{c.Queries, c.PrivilegedQueries} {
		answers, present := queries[QueryHelperTarget]
		if !present {
			continue
		}
		if c.Format != RecordedFormat && c.Format != recordedFormatHelperTarget {
			return keyNewerFormat("caps: query %q is new in %q, but the format is %q", QueryHelperTarget, recordedFormatHelperTarget, c.Format)
		}
		keys := make([]string, 0, len(answers))
		for key := range answers {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if _, _, _, err := parseHelperTargetKey(key); err != nil {
				return err
			}
			a := answers[key]
			if a.Diffs == nil && a.Unknown == "" && a.Error == "" {
				return fmt.Errorf("caps: helper_target %q is not a diffs / unknown / error answer", key)
			}
			if a.Diffs != nil {
				for _, d := range *a.Diffs {
					if strings.TrimSpace(d) == "" {
						return fmt.Errorf("caps: helper_target %q has empty mismatch text", key)
					}
				}
			}
		}
	}
	return nil
}
