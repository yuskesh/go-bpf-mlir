package requirements

import (
	"strings"
)

// an arena row is arena <map> (format 29, specification
// section 3) — one row per arena map, naming an earlier map row of type arena.
// The kernel's arena capability is asked by the map row (map_type) and the
// kfield rows; the arena row asks the loader only. Two loader contracts decide
// whether an arena object can work under the loader:
//
//   - arena_cast: the loader passes the program's instructions to the kernel
//     byte for byte (preserve), or rewrites addr_space_cast (corrupt — U3: the
//     cilium v0.22 asm Marshal drops the cast's offset 1 to 0, and 7.1.8 rejects
//     the program with "BPF_MOV uses reserved fields").
//   - arena_premmap: the loader mmaps the arena at its map_extra address right
//     after creating it, sharing it with userspace (create_then_mmap), or does
//     not (none).
//
// Check: preserve and create_then_mmap satisfy the row; a definite corrupt or
// none blocks with arena_loader; otherwise an undeclared key blocks with
// arena_loader_unknown.

// ArenaMinVersion is the first format that can contain arena rows.
const ArenaMinVersion = 29

// parseArena reads an arena row: the map row comes first (order) and has type
// arena (value); rows are in strictly increasing map order (order — a second
// row for the same map too).
func (r *Requirements) parseArena(n int, f []string, line string) error {
	var mp *Map
	for i := range r.Maps {
		if r.Maps[i].Symbol == f[1] {
			mp = &r.Maps[i]
		}
	}
	if mp == nil {
		return perr(n, f[0], RuleOrder, "%s line %d: arena row for %q, which is not an earlier map row", Section, n, f[1])
	}
	if mp.MapType != "arena" {
		return perr(n, f[0], RuleValue, "%s line %d: arena row for %q, which is a %s map, not an arena map (%q)", Section, n, f[1], mp.MapType, line)
	}
	if k := len(r.Arenas); k > 0 && r.Arenas[k-1] >= f[1] {
		return perr(n, f[0], RuleOrder, "%s line %d: arena rows must be in strictly increasing map order, got %q after %q", Section, n, f[1], r.Arenas[k-1])
	}
	r.Arenas = append(r.Arenas, f[1])
	return nil
}

// checkArenaRows is the end-of-document reverse rule: from format 29, every
// arena map row has exactly one arena row (parseArena already refuses a second
// one). Format 28 and earlier documents are not checked — an older object reads
// as before, without a loader check.
func (r *Requirements) checkArenaRows() error {
	if r.Version < ArenaMinVersion {
		return nil
	}
	for _, m := range r.Maps {
		if m.MapType != "arena" {
			continue
		}
		found := false
		for _, a := range r.Arenas {
			if a == m.Symbol {
				found = true
			}
		}
		if !found {
			return perr(0, "arena", RuleDocument, "%s: map %q is an arena map but has no arena row (format 29 and later)", Section, m.Symbol)
		}
	}
	return nil
}

// checkArenas asks the loader declarations once per arena map.
func checkArenas(req *Requirements, caps Capabilities) []Unmet {
	if len(req.Arenas) == 0 {
		return nil
	}
	decl := loaderOf(caps)
	var definite, undeclared []string
	switch decl.ArenaCast {
	case ArenaCastPreserve:
	case ArenaCastCorrupt:
		definite = append(definite, "arena_cast "+decl.ArenaCast)
	default:
		undeclared = append(undeclared, "arena_cast")
	}
	switch decl.ArenaPremmap {
	case ArenaPremmapCreateThenMmap:
	case ArenaPremmapNone:
		definite = append(definite, "arena_premmap "+decl.ArenaPremmap)
	default:
		undeclared = append(undeclared, "arena_premmap")
	}
	var out []Unmet
	for _, m := range req.Arenas {
		switch {
		case len(definite) > 0:
			out = append(out, Unmet{Kind: "arena_loader", Name: m,
				Detail: "loader " + decl.Name + " declares " + strings.Join(definite, ", ")})
		case len(undeclared) > 0:
			out = append(out, Unmet{Kind: "arena_loader_unknown", Name: m,
				Detail: "loader " + decl.Name + " does not declare " + strings.Join(undeclared, ", ")})
		}
	}
	return out
}
