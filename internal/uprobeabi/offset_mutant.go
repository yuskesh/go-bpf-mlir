//go:build gobpf_uprobe_mutant

package uprobeabi

import "os"

// The mutation of offsetIn (only with the test build tag gobpf_uprobe_mutant): env GOBPF_UPROBE_MUTANT selects a wrong file offset computation.
//
//	vaddr-as-offset (A) — st_value used as the file offset as is (p_vaddr not subtracted, p_offset not added)
//	no-poffset      (B) — st_value − p_vaddr (p_offset not added)
//
// Without the env it computes correctly (the control for the tagged build).
func offsetIn(st, vaddr, off uint64) uint64 {
	switch os.Getenv("GOBPF_UPROBE_MUTANT") {
	case "vaddr-as-offset":
		return st
	case "no-poffset":
		return st - vaddr
	}
	return st - vaddr + off
}

const mutantBuild = true
