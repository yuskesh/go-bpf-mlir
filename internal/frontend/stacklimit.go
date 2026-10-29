package frontend

import (
	"fmt"
	"go/ast"
	"go/types"
	"regexp"
	"strings"
)

// stackLimitRE matches the LLVM BPF backend's stack-limit error in ebpf-compile's stderr (rc ≠ 0) and takes the function name.
var stackLimitRE = regexp.MustCompile(`in function (\S+) [^:]*: Looks like the BPF stack limit is exceeded`)

// StackLimitDiagnostics maps a real ebpf-compile stack-limit failure to a named GB016 when the failing function writes a ring buffer event
// whose record has unnamed `_` padding: record.make leaves the padding bytes uncovered, so bpf-mlir builds the event on the stack instead
// of storing it straight into the reservation. The padding is named as the likely cause, not the only one (the function can overflow its
// stack for another reason); ebpf-compile's own lines stay as the cause after it. One diagnostic per function and map, at the first call.
// No stack-limit line, or no padded ring event in the named function, gives nothing — there is no size threshold and no guess.
func StackLimitDiagnostics(res *Result, stderr string) []Diagnostic {
	if res == nil || res.an == nil {
		return nil
	}
	a := res.an
	var out []Diagnostic
	seen := map[string]bool{}
	for _, line := range strings.Split(stderr, "\n") {
		m := stackLimitRE.FindStringSubmatch(line)
		if m == nil || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		fd := a.funcDeclNamed(m[1])
		if fd == nil || fd.Body == nil {
			continue
		}
		cause := strings.TrimPrefix(strings.TrimSpace(line), "ebpf-compile: ")
		done := map[*BpfMap]bool{}
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := ast.Unparen(call.Fun).(*ast.SelectorExpr)
			if !ok {
				return true
			}
			bm := a.mapOfExpr(sel.X)
			if bm == nil || bm.Kind != "ringbuf" || bm.Value.Record == nil || done[bm] {
				return true
			}
			pads := blankFields(bm.Value.GoType, nil)
			if len(pads) == 0 {
				return true
			}
			done[bm] = true
			rec := bm.Value.Record.Symbol
			out = append(out, Diagnostic{Verdict: Rejected, Code: GB016SharedABIShape, Pos: a.position(call.Pos()), Msg: fmt.Sprintf(
				"ebpf-compile stopped %s at the BPF stack limit — likely cause: the %s event record %s has unnamed padding (%s), so record.make does not cover every byte and ebpf-compile builds the event on the stack instead of storing it into the reservation; name the padding field (for example `Pad uint32` with a schema tag). The overflow can also have another cause — ebpf-compile: %s",
				m[1], bm.Symbol, rec, strings.Join(pads, ", "), cause)})
			return true
		})
	}
	return out
}

// funcDeclNamed returns the package's top-level function with the given name (nil if none).
func (a *analyzer) funcDeclNamed(name string) *ast.FuncDecl {
	for _, f := range a.pkg.Syntax {
		for _, d := range f.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok && fd.Recv == nil && fd.Name.Name == name {
				return fd
			}
		}
	}
	return nil
}

// blankFields lists the `_` fields of t (a struct, nested structs and arrays of structs included) as `<path>_ <type>`.
func blankFields(t types.Type, prefix []string) []string {
	switch u := t.Underlying().(type) {
	case *types.Array:
		return blankFields(u.Elem(), append(prefix, "[]"))
	case *types.Struct:
		var out []string
		for i := 0; i < u.NumFields(); i++ {
			f := u.Field(i)
			if f.Name() == "_" {
				out = append(out, strings.Join(append(append([]string(nil), prefix...), "_ "+types.TypeString(f.Type(), func(*types.Package) string { return "" })), "."))
				continue
			}
			out = append(out, blankFields(f.Type(), append(prefix, f.Name()))...)
		}
		return out
	}
	return nil
}
