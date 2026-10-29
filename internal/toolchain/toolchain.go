// Package toolchain checks the version of the ebpf-compile that gobpf uses.
//
// Since v0.3.0, `ebpf-compile --version` prints a line `bpf-mlir <git describe> (commit <sha>)`. gobpf checks the compiler against
// **one pinned commit** (PinnedCompilerCommit) and the bpf-mlir/go module against a pinned version (PinnedModuleVersion) (previously the describe
// was exactly `go/<module version>`, but the compiler and the Go module are now at different commits). Unless all four of the following
// hold, gobpf stops with a named error without calling ebpf-compile — there is no path (flag, environment variable) that skips the check:
//
//  1. the --version commit is PinnedCompilerCommit (the describe is only written to the provenance — the version string is not checked)
//  2. the describe does not end in `-dirty` and is not `unknown` (a build from source changed from the pinned commit is refused)
//  3. the bpf-mlir/go module version gobpf was built with (BuildModuleVersion — when replaced or `(devel)` it cannot be checked, so it
//     stops) is PinnedModuleVersion
//  4. when the module has third_party/bpf-mlir (the development submodule in the go-bpf-mlir repo), its HEAD commit equals the --version commit
//
// The pins are in a pair of files selected by the build tag gobpf_public: pin_dev.go (the development repository — a bpf-mlir commit and
// the bpf-mlir/go module) and pin_public.go (the public tree — the bpf-mlir v1.20.0 source release, with the bpf-mlir Go packages copied in,
// so the module version is the tree itself).
package toolchain

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Verified holds the checked values (written to the provenance comment).
type Verified struct {
	Describe  string // the --version describe (for example go/v1.19.0-54-gab0db4b40 — not checked)
	Commit    string // the --version commit
	Module    string // the bpf-mlir/go version gobpf was built with
	Submodule string // the HEAD of third_party/bpf-mlir ("" means no submodule)
}

var versionLine = regexp.MustCompile(`(?m)^\s*bpf-mlir (\S+) \(commit (\S+)\)\s*$`)

// Verify checks the --version output, the module version and the submodule commit ("" means none).
func Verify(versionOutput, moduleVersion, submoduleCommit string) (Verified, error) {
	fix := compilerFix
	m := versionLine.FindStringSubmatch(versionOutput)
	if m == nil {
		return Verified{}, fmt.Errorf("ebpf-compile --version has no `bpf-mlir <version> (commit <sha>)` line (bpf-mlir before v0.3.0?) — gobpf needs bpf-mlir commit %s; %s", PinnedCompilerCommit, fix)
	}
	v := Verified{Describe: m[1], Commit: m[2], Module: moduleVersion, Submodule: submoduleCommit}
	if v.Commit != PinnedCompilerCommit {
		return v, fmt.Errorf("ebpf-compile is bpf-mlir %s (commit %s), but gobpf needs exactly bpf-mlir commit %s; %s", v.Describe, v.Commit, PinnedCompilerCommit, fix)
	}
	if strings.HasSuffix(v.Describe, "-dirty") || v.Describe == "unknown" {
		return v, fmt.Errorf("ebpf-compile is bpf-mlir %q (commit %s), a build from modified or unidentified source: gobpf refuses it; %s", v.Describe, v.Commit, fix)
	}
	if err := checkModule(moduleVersion); err != nil {
		return v, err
	}
	if submoduleCommit != "" && submoduleCommit != v.Commit {
		return v, fmt.Errorf("ebpf-compile was built from bpf-mlir commit %s but third_party/bpf-mlir is at %s — rebuild with scripts/setup.sh", v.Commit, submoduleCommit)
	}
	return v, nil
}

// SubmoduleCommit returns the HEAD of moduleDir/third_party/bpf-mlir ("" if absent).
func SubmoduleCommit(moduleDir string) (string, error) {
	return submoduleHead(moduleDir, "bpf-mlir")
}

// CiliumForkCommit returns the HEAD of moduleDir/third_party/cilium-ebpf (the local fork of cilium/ebpf) ("" if absent).
func CiliumForkCommit(moduleDir string) (string, error) {
	return submoduleHead(moduleDir, "cilium-ebpf")
}

func submoduleHead(moduleDir, name string) (string, error) {
	if moduleDir == "" {
		return "", nil
	}
	sub := filepath.Join(moduleDir, "third_party", name)
	if _, err := os.Stat(filepath.Join(sub, ".git")); err != nil {
		return "", nil
	}
	out, err := exec.Command("git", "-C", sub, "rev-parse", "HEAD").Output()
	if err != nil {
		return "", fmt.Errorf("reading the commit of %s: %w", sub, err)
	}
	return strings.TrimSpace(string(out)), nil
}

// Check reads the compiler's --version and checks it against gobpf's build information and the module's submodule.
func Check(compiler, moduleDir string) (Verified, error) {
	out, err := exec.Command(compiler, "--version").CombinedOutput()
	if err != nil {
		return Verified{}, fmt.Errorf("running %s --version: %w", compiler, err)
	}
	mod, err := BuildModuleVersion()
	if err != nil {
		return Verified{}, err
	}
	sub, err := SubmoduleCommit(moduleDir)
	if err != nil {
		return Verified{}, err
	}
	return Verify(string(out), mod, sub)
}

var diagLoc = regexp.MustCompile(`^loc\("([^"]+)":(\d+):(\d+)\): (.*)$`)

// RewriteLocs rewrites ebpf-compile diagnostic lines `loc("F":L:C): <msg>` to `<dir>/F:L:C: ebpf-compile: <msg>` (the
// frontend gives each .mlir op a loc with its Go position, F relative to the package directory) — a shape an editor can jump to the Go line from.
// **Lines without a loc (ebpf-compile's own errors, `loc(unknown)` ops, note continuations) are printed unchanged**. The rewrite only changes display, never the verdict.
func RewriteLocs(output, dir string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimRight(output, "\n"), "\n") {
		if m := diagLoc.FindStringSubmatch(line); m != nil && !filepath.IsAbs(m[1]) {
			fmt.Fprintf(&b, "%s:%s:%s: ebpf-compile: %s\n", filepath.Join(dir, m[1]), m[2], m[3], m[4])
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// ebpf-compile's stderr with rc 0 (the first warnings came with bpf-mlir v0.10.0).
//
//	loc("F":L:C): warning: <text>
//	loc("F":L:C): note: <text>          (continues the preceding warning — for example: the constant index comes from here)
//
// If stderr with rc 0 has a line not in one of these two shapes, gobpf **stops generation** (a new ebpf-compile output shape is never silently dropped — fail closed).
// A warning does not stop generation (a frontend Conditional — GB024).

// CompileNote is one ebpf-compile diagnostic line (F is relative to the package directory — the frontend's loc).
type CompileNote struct {
	File      string
	Line, Col int
	Msg       string
}

// CompileWarning is a warning and the notes after it.
type CompileWarning struct {
	CompileNote
	Notes []CompileNote
}

var warnLine = regexp.MustCompile(`^loc\("([^"]+)":(\d+):(\d+)\): (warning|note): (.*)$`)

// CompileWarnings reads ebpf-compile's stderr with rc 0. A line not in warning / note shape (except blank lines) is an error.
func CompileWarnings(stderr string) ([]CompileWarning, error) {
	var out []CompileWarning
	for _, line := range strings.Split(stderr, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		m := warnLine.FindStringSubmatch(line)
		if m == nil || (m[4] == "note" && len(out) == 0) {
			return nil, fmt.Errorf("ebpf-compile succeeded but printed a line gobpf does not read — a new ebpf-compile output form, update gobpf's reading of it — the line: %s", line)
		}
		var n CompileNote
		n.File, n.Msg = m[1], m[5]
		fmt.Sscanf(m[2], "%d", &n.Line)
		fmt.Sscanf(m[3], "%d", &n.Col)
		if m[4] == "warning" {
			out = append(out, CompileWarning{CompileNote: n})
		} else {
			out[len(out)-1].Notes = append(out[len(out)-1].Notes, n)
		}
	}
	return out, nil
}
