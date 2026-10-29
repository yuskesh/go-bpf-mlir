package main

import (
	"fmt"

	"github.com/yuskesh/go-bpf-mlir/bpf"
)

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

// Bad is a capability error (go.runtime) — it is not lowered.
func Bad(x uint32) uint32 {
	fmt.Println(x)
	return x
}

// Shape is a shape error (a shift by the width or more — GB012).
func Shape(x uint32) uint32 { return x << 32 }

// P calls Bad, but the call's shape is correct (no false error). The check goes on to P's own shape error after it.
func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(Bad(1)+Shape(2)))
	var y uint32 = 1
	Counts.Update(1, uint64(y>>40))
	return bpf.XDPPass
}

func main() {}
