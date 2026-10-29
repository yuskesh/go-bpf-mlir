package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A nil check of a subprogram's unchecked borrowed argument inside another checked branch — the current rule (GB001, unchanged).
type Rec struct {
	X uint64 `schema:"x"`
}

type Acc struct {
	S uint64 `schema:"s"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}
var B = bpf.Array[uint32, Acc]{MaxEntries: 4}

func get(p *Rec) uint64 {
	v := uint64(0)
	if q := B.Lookup(0); q != nil {
		if p != nil {
			v = p.X + q.S
		}
	}
	return v
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	B.Update(1, Acc{S: get(A.Lookup(0))})
	return bpf.XDPPass
}

func main() {}
