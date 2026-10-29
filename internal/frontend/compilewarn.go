package frontend

import (
	"fmt"
	"go/token"
	"strings"

	tc "github.com/yuskesh/go-bpf-mlir/internal/toolchain"
)

// CompileWarningDiagnostics turns ebpf-compile warnings (stderr with rc 0 — toolchain.CompileWarnings) into Conditional diagnostics
// GB024 with Go positions. Treated like GB020 — generation does not stop, and they stay in go generate's output and the generated file's conditional section. A note's
// position (for example "the constant index comes from here") is also added to the text as a Go position (F:L:C relative to the package directory).
func CompileWarningDiagnostics(ws []tc.CompileWarning) []Diagnostic {
	var out []Diagnostic
	for _, w := range ws {
		var b strings.Builder
		fmt.Fprintf(&b, "ebpf-compile: %s", w.Msg)
		for _, n := range w.Notes {
			fmt.Fprintf(&b, " (note at %s:%d:%d: %s)", n.File, n.Line, n.Col, n.Msg)
		}
		out = append(out, Diagnostic{Verdict: Conditional, Code: GB024CompileWarning, Pos: token.Position{Filename: w.File, Line: w.Line, Column: w.Col}, Msg: b.String()})
	}
	return out
}
