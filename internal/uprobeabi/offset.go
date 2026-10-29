//go:build !gobpf_uprobe_mutant

package uprobeabi

// offsetIn returns the file offset of the symbol vaddr st inside the executable PT_LOAD containing it (vaddr, file offset) (the uprobe attach Address).
// Only a build with the test build tag gobpf_uprobe_mutant swaps in the mutation (offset_mutant.go). This build has no entry to it.
func offsetIn(st, vaddr, off uint64) uint64 { return st - vaddr + off }

// mutantBuild reports whether this build has the mutation entry (false without the tag — see TestNoMutantInProductBuild).
const mutantBuild = false
