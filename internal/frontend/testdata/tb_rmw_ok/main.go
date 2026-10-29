package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Controls: q.S = p.X + 1 (a read of a different borrow), a copy between different constant keys of the same map, and a Lookup of a
// different value type inside a borrowed argument of p's type (a different value) are not GB028 / GB029.
type Rec struct {
	X uint64 `schema:"x"`
}

type Acc struct {
	S uint64 `schema:"s"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}
var B = bpf.Array[uint32, Acc]{MaxEntries: 4}

func peek(p *Rec) uint64 {
	v := p.X
	if q := B.Lookup(3); q != nil {
		v = q.S + p.X
	}
	return v
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(0); p != nil {
		if q := B.Lookup(0); q != nil {
			q.S = p.X + 1
		}
		if r := A.Lookup(1); r != nil {
			r.X = p.X
		}
		B.Update(2, Acc{S: peek(p)})
	}
	return bpf.XDPPass
}

func main() {}
