package frontend

import (
	"go/ast"
	"strings"
)

// Loop mode directives (bpf-mlir v1.11.0's ebpf.loop (B) and (H)):
//
//	//gobpf:loop backedge
//	for i := uint32(0); i < 64; i++ { … }   → ebpf.loop 64 (…) — without the unroll word (a bounded back-edge)
//	//gobpf:loop callback
//	for i := uint32(0); i < 64; i++ { … }   → ebpf.loop 64 callback (…) — the bpf_loop helper and a static callback
//
// Only a directive on the line just before the for. Without one, (U) unrolling as before. (B) / (H) have no unrolling estimate (N ≤ 64 and the nesting rules are the same); in a (B) body
// ctx.Check is GB018 (in bpf-mlir packet.check is allowed only in a (U) body), and a (H) body cannot use the context (GB018 — only integers and map handles
// can be carried into the callback). There is no automatic fallback.

// loopModes holds the mode names of the directive.
var loopModes = map[string]bool{"backedge": true, "callback": true}

// collectLoopDirectives binds `//gobpf:loop <mode>` to the for / range statement on the next line (a.loopMode). Errors are GB008.
func (a *analyzer) collectLoopDirectives() {
	a.loopMode = map[ast.Stmt]string{}
	for _, f := range a.files() {
		loops := map[int]ast.Stmt{} // start line → for / range statement
		ast.Inspect(f, func(n ast.Node) bool {
			switch s := n.(type) {
			case *ast.ForStmt:
				loops[a.fset.Position(s.Pos()).Line] = s
			case *ast.RangeStmt:
				loops[a.fset.Position(s.Pos()).Line] = s
			}
			return true
		})
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				m := directiveRE.FindStringSubmatch(c.Text)
				if m == nil || m[1] != "loop" {
					continue
				}
				a.directiveOf[cg] = true // the comment group of a loop directive (checkStrayDirectives looks at the other //gobpf: comments)
				mode := strings.TrimSpace(m[2])
				s, ok := loops[a.fset.Position(c.Pos()).Line+1]
				switch {
				case !ok:
					a.report(Rejected, GB008ProgramShape, c.Pos(), nil, "//gobpf:loop must be on the line right above a for statement")
				case !loopModes[mode]:
					a.report(Rejected, GB008ProgramShape, c.Pos(), nil, "//gobpf:loop %q: the loop mode must be backedge or callback (`//gobpf:loop backedge` / `//gobpf:loop callback` — without a directive the loop is unrolled)", mode)
				default: // a second directive cannot be on the line just before the for — the !ok above stops it (one directive per for)
					a.loopMode[s] = mode
				}
			}
		}
	}
}
