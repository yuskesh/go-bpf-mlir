package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Two borrows at once — different maps, writes to the outer inside the inner region and in the absent arm, AtomicAdd on both, a nested record path,
// a borrow of an integer map, different constant keys of the same map.

type Pt struct {
	A uint32 `schema:"a"`
	B uint32 `schema:"b"`
}

type In struct {
	X    uint64 `schema:"x"`
	Seen uint64 `schema:"seen"`
	Miss uint64 `schema:"miss"`
	Pt   Pt     `schema:"pt"`
}

type Acc struct {
	Sum  uint64 `schema:"sum"`
	Last uint64 `schema:"last"`
}

var A = bpf.Array[uint32, In]{MaxEntries: 4}
var B = bpf.Hash[uint32, Acc]{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(0); p != nil {
		if q := B.Lookup(1); q != nil {
			bpf.AtomicAdd(&q.Sum, p.X)    // read the outer, write the inner
			q.Last = p.X + uint64(p.Pt.A) // nested record path
			p.Seen = q.Sum                // write the outer inside the inner region
			bpf.AtomicAdd(&p.X, 1)
		} else {
			p.Miss = 1 // write the outer in the inner absent arm
		}
		if c := C.Lookup(2); c != nil { // borrow of an integer-valued map
			p.Pt.B = uint32(*c)
		}
	}
	if s := A.Lookup(1); s != nil {
		if t := A.Lookup(2); t != nil { // a different constant key of the same map
			t.X = s.X
		}
	}
	return bpf.XDPPass
}

func main() {}
