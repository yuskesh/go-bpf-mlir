package frontend

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"
)

// Path rules for calls inside loops. The frontend applies the same rules as bpf-mlir's ebpf-verify-call-graph
// first, stopping with GB018 (LoopShape) with a Go position and the path in the message (ebpf-compile stays as the backstop):
//
//	R1: the callees (transitively) of a call inside a loop body must not reach a ring buffer operation (RingBuf.Output / OutputStr)
//	R2: the loops on a path from the program entry, counting the caller's loops, have nesting depth ≤ 2 and a count product ≤ 64
//
// The verdict is made at the call: it combines the enclosing loops (in this function) with the callee's summary (its deepest loop and largest product, and ring buffer reach — the call graph is
// a DAG: GB013 stops recursion). For a violating path, loop.go checks the outermost loop when all loops are in the same function, and when the path crosses functions
// the call inside that loop does.

// checkLoopCallPaths turns the path rule check on or off — **only tests set it to false** (the agreement test: .mlir without the frontend check is
// passed to ebpf-compile). It is not a user flag.
var checkLoopCallPaths = true

// loopPath summarizes the loops on a path (depth, product, and the path words for messages).
type loopPath struct {
	depth   int
	product int64
	steps   []string // for example ["loop 8", "loop 8"], ["inner", "loop 8"]
}

// callSummary summarizes a function body (its largest loop paths and ring buffer reach).
type callSummary struct {
	deepest  loopPath // the deepest path
	largest  loopPath // the path with the largest product
	ringPath []string // a path reaching a ring buffer operation (nil if none) — for example ["emit", "Events.Output"]
}

// callSummaryOf returns the summary of subprogram s's body (memoized — the call graph is a DAG).
func (a *analyzer) callSummaryOf(s *Subprogram) callSummary {
	if a.callSums == nil {
		a.callSums = map[*Subprogram]*callSummary{}
	}
	if c, ok := a.callSums[s]; ok {
		if c == nil { // recursion (GB013 stops it — here it ends with an empty summary)
			return callSummary{}
		}
		return *c
	}
	a.callSums[s] = nil
	c := a.summarizeBody(s.decl.Body)
	a.callSums[s] = &c
	return c
}

// summarizeBody walks the body's loop nesting, calls and ring buffer operations.
func (a *analyzer) summarizeBody(body *ast.BlockStmt) callSummary {
	var out callSummary
	var walk func(n ast.Node, depth int, product int64, steps []string)
	better := func(p loopPath) {
		if p.depth > out.deepest.depth {
			out.deepest = p
		}
		if p.product > out.largest.product {
			out.largest = p
		}
	}
	walk = func(n ast.Node, depth int, product int64, steps []string) {
		ast.Inspect(n, func(m ast.Node) bool {
			switch x := m.(type) {
			case *ast.FuncLit:
				return false
			case *ast.ForStmt, *ast.RangeStmt:
				if m == n {
					return true
				}
				_, count, _, lbody, reason := a.loopShape(x.(ast.Stmt))
				if reason != "" || lbody == nil {
					return false // loop.go reports shape errors
				}
				st := append(append([]string{}, steps...), fmt.Sprintf("loop %d", count))
				p := loopPath{depth + 1, product * count, st}
				better(p)
				walk(lbody, depth+1, product*count, st)
				return false
			case *ast.CallExpr:
				if name, ok := a.ringOp(x); ok {
					if out.ringPath == nil {
						out.ringPath = []string{name}
					}
					return true
				}
				if id, ok := x.Fun.(*ast.Ident); ok {
					if fn := a.samePkgFunc(id); fn != nil {
						if s := a.subByObj[fn]; s != nil && s.decl != nil {
							c := a.callSummaryOf(s)
							st := append(append([]string{}, steps...), s.Symbol)
							if c.deepest.depth > 0 {
								better(loopPath{depth + c.deepest.depth, product * c.deepest.product, append(append([]string{}, st...), c.deepest.steps...)})
							}
							if c.largest.depth > 0 {
								better(loopPath{depth + c.largest.depth, product * c.largest.product, append(append([]string{}, st...), c.largest.steps...)})
							}
							if c.ringPath != nil && out.ringPath == nil {
								out.ringPath = append([]string{s.Symbol}, c.ringPath...)
							}
						}
					}
				}
			}
			return true
		})
	}
	walk(body, 0, 1, nil)
	return out
}

// ringOp returns the name "M.Output" if call is a ring buffer operation (RingBuf.Output / OutputStr / OutputKernelStr).
func (a *analyzer) ringOp(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || (sel.Sel.Name != "Output" && sel.Sel.Name != "OutputStr" && sel.Sel.Name != "OutputStrOrDiscard" && sel.Sel.Name != "OutputKernelStr") {
		return "", false
	}
	fn, ok := a.info.Uses[sel.Sel].(*types.Func)
	if !ok {
		return "", false
	}
	recv := fn.Type().(*types.Signature).Recv()
	if recv == nil {
		return "", false
	}
	t := recv.Type()
	if p, ok := t.(*types.Pointer); ok {
		t = p.Elem()
	}
	named, ok := t.(*types.Named)
	if !ok || named.Obj().Pkg() == nil || named.Obj().Pkg().Path() != bpfPkg || named.Obj().Name() != "RingBuf" {
		return "", false
	}
	return types.ExprString(sel), true
}

// checkCallInLoop checks the path rules R1 / R2 for a call (of s) inside a loop body. false means it reported an error.
func (l *lowerer) checkCallInLoop(call *ast.CallExpr, s *Subprogram) bool {
	if !checkLoopCallPaths || len(l.loops) == 0 {
		return true
	}
	// The path words, depth and product of the enclosing loops (outer to inner).
	var steps []string
	product := int64(1)
	for i := len(l.loops) - 1; i >= 0; i-- {
		steps = append(steps, fmt.Sprintf("loop %d", l.loops[i].count))
		product *= l.loops[i].count
	}
	depth := len(l.loops)
	c := l.a.callSummaryOf(s)
	path := func(tail []string) string {
		return strings.Join(append(append(append([]string{l.name}, steps...), s.Symbol), tail...), " → ")
	}
	if c.ringPath != nil {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "%s is called inside a loop and reaches the ring buffer (%s) — a function called from a loop may not use a ring buffer (bpf-mlir's call graph check); call it after the loop", s.Symbol, path(c.ringPath))
		return false
	}
	if c.deepest.depth > 0 && depth+c.deepest.depth > loopMaxDepth {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "loops nest %d deep along %s — at most %d, counting the loops of every caller on the path (bpf-mlir's ebpf.loop)", depth+c.deepest.depth, path(c.deepest.steps), loopMaxDepth)
		return false
	}
	if c.largest.depth > 0 && product*c.largest.product > loopMaxProduct {
		l.fail(Rejected, GB018LoopShape, call.Pos(), "the loop counts along %s multiply to %d — at most %d, counting the loops of every caller on the path (bpf-mlir's ebpf.loop)", path(c.largest.steps), product*c.largest.product, loopMaxProduct)
		return false
	}
	return true
}
