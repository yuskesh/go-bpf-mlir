package requirements

import (
	"strings"
)

// a datakptr row is datakptr <section> (format 23,
// specification section 3) — a .data.<name> section of hidden kptr globals
// (C's private(name) struct T __kptr *). The kernel makes the kptr part of the
// data map's record, and refuses mmap of a map with a record (-ENOTSUPP), so the
// loader must not mmap the section's hidden variables. That is a loader
// contract, not a kernel fact: Check asks the loader declaration
// hidden_data_vars only (no_mmap satisfies it; mmap blocks with datakptr_loader,
// undeclared blocks with datakptr_loader_unknown). A kernel without the DATASEC
// kptr record rejects the program's kptr_xchg loudly at verification.

// DataKptrMinVersion is the first format that can contain datakptr rows.
const DataKptrMinVersion = 23

// validDataKptrSection is .data.<name> with a name of letters, digits and '_'
// (the compiler's "data:<name>" schema section).
func validDataKptrSection(s string) bool {
	name, ok := strings.CutPrefix(s, ".data.")
	if !ok || name == "" {
		return false
	}
	for _, c := range name {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// parseDataKptr reads a datakptr row: a valid section name, rows in strictly
// increasing byte order (no duplicates).
func (r *Requirements) parseDataKptr(n int, f []string, line string) error {
	if !validDataKptrSection(f[1]) {
		return perr(n, f[0], RuleValue, "%s line %d: bad datakptr row %q (want .data.<name>, a name of letters, digits and '_')", Section, n, line)
	}
	if k := len(r.DataKptrs); k > 0 && r.DataKptrs[k-1] >= f[1] {
		return perr(n, f[0], RuleOrder, "%s line %d: datakptr rows must be in strictly increasing section order, got %q after %q", Section, n, f[1], r.DataKptrs[k-1])
	}
	r.DataKptrs = append(r.DataKptrs, f[1])
	return nil
}

// checkDataKptrs asks the loader declaration once per section.
func checkDataKptrs(req *Requirements, caps Capabilities) []Unmet {
	decl := loaderOf(caps)
	var out []Unmet
	for _, sec := range req.DataKptrs {
		switch decl.HiddenDataVars {
		case HiddenDataVarsNoMmap:
		case HiddenDataVarsMmap:
			out = append(out, Unmet{Kind: "datakptr_loader", Name: sec,
				Detail: "loader " + decl.Name + " declares hidden_data_vars mmap"})
		default:
			out = append(out, Unmet{Kind: "datakptr_loader_unknown", Name: sec,
				Detail: "loader " + decl.Name + " does not declare hidden_data_vars"})
		}
	}
	return out
}
