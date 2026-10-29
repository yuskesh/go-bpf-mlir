package requirements

import (
	"fmt"
	"strings"
)

func validKFieldIdentifier(s string) bool {
	if s == "" {
		return false
	}
	for i, c := range s {
		if !(c == '_' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || i > 0 && c >= '0' && c <= '9') {
			return false
		}
	}
	return true
}
func validKFieldPath(s string) bool {
	ps := strings.Split(s, ".")
	if len(ps) > 3 {
		return false
	}
	for _, p := range ps {
		if !validKFieldIdentifier(p) {
			return false
		}
	}
	return true
}
func checkKFieldPrefixes(rows []KField) error {
	type key struct{ p, s, f string }
	prefixes := map[key]string{}
	for _, r := range rows {
		if strings.HasPrefix(r.Type, "struct:") {
			k := key{r.Program, r.Struct, r.Field}
			if old, ok := prefixes[k]; ok && old != r.Type {
				return fmt.Errorf("conflicting embedded kfield prefix %s.%s", r.Struct, r.Field)
			}
			prefixes[k] = r.Type
		}
	}
	for _, r := range rows {
		ps := strings.Split(r.Field, ".")
		for i := 1; i < len(ps); i++ {
			p := strings.Join(ps[:i], ".")
			if prefixes[key{r.Program, r.Struct, p}] == "" {
				return fmt.Errorf("missing embedded kfield struct prefix %s.%s", r.Struct, p)
			}
		}
	}
	return nil
}
