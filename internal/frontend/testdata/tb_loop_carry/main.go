package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Carries an outer borrow into a loop — the current rule (GB018). A second Lookup inside the loop is accepted, but the outer p cannot be used in the loop.
type Rec struct {
	X uint64 `schema:"x"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}
var B = bpf.Array[uint32, Rec]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(0); p != nil {
		for i := range uint32(4) {
			if q := B.Lookup(i); q != nil {
				q.X = p.X
			}
		}
	}
	return bpf.XDPPass
}

func main() {}
