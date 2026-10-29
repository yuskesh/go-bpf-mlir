package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Two borrows of the same map with the same constant key — the same value (GB029).
type Rec struct {
	X uint64 `schema:"x"`
	Y uint64 `schema:"y"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(1); p != nil {
		if q := A.Lookup(1); q != nil {
			q.Y = p.X
		}
	}
	return bpf.XDPPass
}

func main() {}
