package requirements

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// PrivilegeDependentQueries lists load-probe queries whose answers depend on
// the probing process's capabilities. Other known queries inspect files or
// kernel metadata. Recorded caps separate these as privileged_queries and
// queries. ForLoad re-probes or yields Unknown when load privileges differ;
// a recorded root answer must not authorize a non-root load. See
// docs/requirements_format.md section 10 for the query privilege table.
var PrivilegeDependentQueries = []string{
	QueryProgType, QueryHelper, QueryMapType, QueryTCX, QueryNetkit, QueryBTFFeature, QueryArgTag, QueryMapField, QueryNullableArgs,
	QueryTracingHelper, QueryAttachType, QueryCtxAccess, QuerySleepable, // the pair probe loads a program.
	QueryHelperTarget,
	QueryFibLookupFlags, // the probe loads an XDP program.
	QueryKfuncLoad,      // Exact-profile program-load acceptance depends on effective capabilities.
}

// PrivilegeDependent reports whether query q depends on probe privileges.
func PrivilegeDependent(q string) bool {
	for _, d := range PrivilegeDependentQueries {
		if d == q {
			return true
		}
	}
	return false
}

// SamePrivilege compares valid 64-bit hexadecimal CapEff values, not UIDs.
// BPF checks capabilities (bpf/perfmon capable, NET_ADMIN and SYS_ADMIN).
// Missing or unreadable CapEff never establishes equality.
func SamePrivilege(a, b ProbedAs) bool {
	x, e1 := strconv.ParseUint(strings.TrimSpace(a.CapEff), 16, 64)
	y, e2 := strconv.ParseUint(strings.TrimSpace(b.CapEff), 16, 64)
	return e1 == nil && e2 == nil && a.CapEff != "" && b.CapEff != "" && x == y
}

// CurrentPrivilege reads effective UID and CapEff from /proc/self/status.
// An unreadable CapEff is left empty.
func CurrentPrivilege() ProbedAs {
	p := ProbedAs{UID: os.Geteuid()}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, l := range strings.Split(string(data), "\n") {
			if v, ok := strings.CutPrefix(l, "CapEff:"); ok {
				p.CapEff = strings.TrimSpace(v)
			}
		}
	}
	return p
}

// ParseLoadAs parses <uid>:<cap_eff> for ebpf-precheck --load-as.
func ParseLoadAs(s string) (ProbedAs, error) {
	u, c, ok := strings.Cut(s, ":")
	uid, err := strconv.Atoi(u)
	if !ok || err != nil || uid < 0 {
		return ProbedAs{}, fmt.Errorf("load-as %q: want <uid>:<cap_eff hex>", s)
	}
	if _, err := strconv.ParseUint(c, 16, 64); err != nil || c == "" {
		return ProbedAs{}, fmt.Errorf("load-as %q: the cap_eff is 64-bit hex (/proc/<pid>/status CapEff)", s)
	}
	return ProbedAs{UID: uid, CapEff: c}, nil
}

// loadScope retains ForLoad's intended privileges and re-probe capabilities.
type loadScope struct {
	loadAs   ProbedAs
	reprobe  Capabilities
	mismatch bool // Recorded and load privileges differ, including a missing probed_as.
}

// ForLoad returns caps for loadAs without mutating c. If SamePrivilege cannot
// establish equality, privilege-dependent queries use reprobe, which must run
// on the same target with load privileges, or Unknown when reprobe is nil.
// Other queries, and queries under equal privileges, retain recorded answers.
func (c *RecordedCaps) ForLoad(loadAs ProbedAs, reprobe Capabilities) *RecordedCaps {
	d := *c
	d.scope = &loadScope{loadAs: loadAs, reprobe: reprobe, mismatch: c.ProbedAs == nil || !SamePrivilege(*c.ProbedAs, loadAs)}
	return &d
}

// LoadAs returns ForLoad's intended privileges, or nil before ForLoad.
func (c *RecordedCaps) LoadAs() *ProbedAs {
	if c.scope == nil {
		return nil
	}
	p := c.scope.loadAs
	return &p
}

// privileged selects a recorded answer (use), a re-probe (r), or Unknown (err).
func (c *RecordedCaps) privileged(q string) (r Capabilities, err error, use bool) {
	if c.scope == nil || !c.scope.mismatch || !PrivilegeDependent(q) {
		return nil, nil, true
	}
	if c.scope.reprobe != nil {
		return c.scope.reprobe, nil, false
	}
	rec := "no probed_as"
	if c.ProbedAs != nil {
		rec = fmt.Sprintf("uid %d cap_eff %s", c.ProbedAs.UID, c.ProbedAs.CapEff)
	}
	return nil, unknownErr(fmt.Sprintf("recorded caps: %s depends on the probing privilege — recorded as %s, the load runs as uid %d cap_eff %s (record as the loading privilege, or re-probe it live)",
		q, rec, c.scope.loadAs.UID, c.scope.loadAs.CapEff)), false
}

// reprobeHas requires both the Go interface and QuerySet evidence for q.
func reprobeHas(r Capabilities, q string) bool {
	if qs, ok := r.(QuerySet); ok && !qs.HasQuery(q) {
		return false
	}
	var ok bool
	switch q {
	case QueryProgType, QueryHelper, QueryMapType:
		ok = true
	case QueryTCX:
		_, ok = r.(TCXCaps)
	case QuerySleepable:
		_, ok = r.(SleepableCaps)
	case QueryNetkit:
		_, ok = r.(NetkitCaps)
	case QueryHelperTarget:
		_, ok = r.(TargetHelperCaps)
	case QueryBTFFeature:
		_, ok = r.(BTFFeatureCaps)
	case QueryArgTag:
		_, ok = r.(ArgTagCaps)
	case QueryMapField:
		_, ok = r.(MapFieldPolicy)
	case QueryNullableArgs:
		_, ok = r.(NullableArgCaps)
	case QueryTracingHelper:
		_, ok = r.(TracingHelperCaps)
	case QueryAttachType:
		_, ok = r.(AttachTypeCaps)
	case QueryCtxAccess:
		_, ok = r.(CtxAccessCaps)
	case QueryKfuncLoad:
		_, ok = r.(KernelKfuncLoadCaps)
	}
	return ok
}

// noReprobe reports Unknown for an unavailable re-probe query. Normally
// HasQuery rejects this before the query method is called.
func noReprobe(q string) error {
	return unknownErr("recorded caps: the re-probing caps has no " + q + " query")
}
