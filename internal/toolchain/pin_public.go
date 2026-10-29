package toolchain

import "fmt"

// PinnedCompilerCommit is the bpf-mlir commit of the ebpf-compile gobpf uses: the commit of the bpf-mlir source release.
const PinnedCompilerCommit = ReleaseCompilerCommit

// PinnedCompilerVersion is the bpf-mlir release of PinnedCompilerCommit.
const PinnedCompilerVersion = ReleaseCompilerVersion

// PinnedModuleVersion stands for the bpf-mlir Go binding packages: they are copied into this tree, so their version is this tree.
const PinnedModuleVersion = "none (the bpf-mlir Go packages are copied into go-bpf-mlir)"

// compilerFix is the remedy named by every compiler check error.
const compilerFix = "build ebpf-compile from the bpf-mlir " + PinnedCompilerVersion + " source release (commit " + PinnedCompilerCommit + ") and point EBPF_COMPILE at it"

// BuildModuleVersion is PinnedModuleVersion: there is no separate bpf-mlir Go module to check.
func BuildModuleVersion() (string, error) {
	return PinnedModuleVersion, nil
}

func checkModule(moduleVersion string) error {
	if moduleVersion != PinnedModuleVersion {
		return fmt.Errorf("module version %q given, but the bpf-mlir Go packages are copied into this tree (%s)", moduleVersion, PinnedModuleVersion)
	}
	return nil
}
