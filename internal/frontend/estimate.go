package frontend

import (
	"fmt"
	"strings"
)

// The estimate of (U) unrolling size — counts **the same rules as regionSize / loopCost / expandedWeight in bpf-mlir's lib/Dialect/EBPF/IR/EBPFDialect.cpp**
// over the generated text. bpf-mlir's LoopOp::verify refuses a (U) loop whose loopCost exceeds kMaxUnrolledOps (4096). The frontend
// reports GB018 with a position first, by the same count (the earlier "body op lines × N" had neither the weights nor the +4 per copy and drifted from bpf-mlir).
// Follow bpf-mlir when its counting changes (when updating the bpf-mlir version). The boundary tests: estimate_test.go.
//
//   regionSize(r) = Σ op ∈ r: (loopCost(op) if op is a loop, else expandedWeight(op) + Σ regionSize of that op's regions)
//   loopCost(U)   = N × (regionSize(body) + 4)            (saturates at 4097)
//   expandedWeight: ebpf.map.atomic_add = 6, ebpf.if / ebpf.ref.check / ebpf.ringbuf.if_reserved / scf.if = 4, others = 1 (including terminators)

const (
	unrollCopyOverhead = 4 // bpf-mlir's kUnrollCopyOverhead
	unrollSaturate     = unrollMaxOps + 1
)

func satAdd(a, b uint64) uint64 { return min(a+b, unrollSaturate) }

func satMul(a, b uint64) uint64 {
	if a != 0 && b > unrollSaturate/a {
		return unrollSaturate
	}
	return min(a*b, unrollSaturate)
}

func expandedWeight(op string) uint64 {
	switch op {
	case "ebpf.map.atomic_add":
		return 6
	case "ebpf.if", "ebpf.ref.check", "ebpf.ringbuf.if_reserved", "scf.if":
		return 4
	}
	return 1
}

// estNode is an op of the generated text (with the ops in its regions as children).
type estNode struct {
	op    string
	count uint64 // N of ebpf.loop
	kids  []*estNode
}

// parseOps turns region text (one op per line — a region opens with `{` at the line end and closes with `}` at the line start) into an op tree.
func parseOps(text string) ([]*estNode, error) {
	root := &estNode{}
	stack := []*estNode{root}
	for _, line := range strings.Split(text, "\n") {
		s := strings.TrimSpace(line)
		if i := strings.Index(s, " loc("); i >= 0 {
			s = strings.TrimSpace(s[:i]) // ignore `{` / `}` inside loc
		}
		switch {
		case s == "", strings.HasPrefix(s, "//"), strings.HasPrefix(s, "^"):
			continue
		case strings.HasPrefix(s, "}"):
			if len(stack) < 2 {
				return nil, fmt.Errorf("unbalanced region close: %q", line)
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if strings.HasSuffix(s, "{") { // `} else {` / `} out_of_range {` — the next region of the same op
				stack = append(stack, top)
			}
			continue
		}
		ops := mlirOps(s)
		if len(ops) != 1 {
			return nil, fmt.Errorf("cannot read the op of %q", line)
		}
		n := &estNode{op: ops[0]}
		if n.op == "ebpf.loop" {
			if _, err := fmt.Sscanf(s[strings.Index(s, "ebpf.loop"):], "ebpf.loop %d", &n.count); err != nil {
				return nil, fmt.Errorf("cannot read the count of %q", line)
			}
		}
		parent := stack[len(stack)-1]
		parent.kids = append(parent.kids, n)
		if strings.HasSuffix(s, "{") {
			stack = append(stack, n)
		}
	}
	if len(stack) != 1 {
		return nil, fmt.Errorf("unbalanced regions (%d open)", len(stack)-1)
	}
	return root.kids, nil
}

func regionSize(ops []*estNode) uint64 {
	n := uint64(0)
	for _, op := range ops {
		if op.op == "ebpf.loop" {
			n = satAdd(n, loopCost(op.count, op.kids))
			continue
		}
		n = satAdd(n, expandedWeight(op.op))
		n = satAdd(n, regionSize(op.kids))
	}
	return n
}

// loopCost is the estimate of a (U) loop ((B) / (H) loops have no unrolling estimate).
func loopCost(count uint64, body []*estNode) uint64 {
	return satMul(count, satAdd(regionSize(body), unrollCopyOverhead))
}

// unrollEstimate returns (the body estimate B, the loop estimate N × (B + 4)) from the (U) loop body text and N.
func unrollEstimate(bodyText string, count int64) (body, cost uint64, err error) {
	ops, err := parseOps(bodyText)
	if err != nil {
		return 0, 0, err
	}
	return regionSize(ops), loopCost(uint64(count), ops), nil
}

// unrollLimitCheck is the frontend's (U) unrolling limit check (tests turn it off to compare over-limit .mlir with bpf-mlir's verdict — estimate_test.go).
var unrollLimitCheck = true
