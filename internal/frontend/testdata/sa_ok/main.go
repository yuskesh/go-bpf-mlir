package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Accepted shapes: (A) a checked borrow → borrowed (static / global), (B) an unchecked M.Lookup(k) passed directly → maybe_ref (static / global),
// a global with integers only.
type Rec struct {
	A uint64 `schema:"a"`
	B uint64 `schema:"b"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 8}

func total(p *Rec) uint64 { return p.A + p.B*3 }

//gobpf:global
func totalG(p *Rec) uint64 { return p.A ^ p.B }

func twice(p *uint64) uint64 { return *p * 2 }

func orZero(p *uint64) uint64 {
	v := uint64(7)
	if p != nil {
		v = *p + 1
	}
	return v
}

//gobpf:global
func sumG(p *Rec) uint64 {
	v := uint64(0)
	if p != nil {
		v = p.A + p.B
	} else {
		v = 99
	}
	return v
}

//gobpf:global
func sqG(x uint64) uint64 { return x * x }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	t := uint64(0)
	if p := R.Lookup(0); p != nil {
		t = total(p) + totalG(p)
	}
	if q := C.Lookup(0); q != nil {
		t += twice(q)
	}
	Out.Update(0, t)
	Out.Update(1, orZero(C.Lookup(1)))
	Out.Update(2, sumG(R.Lookup(2)))
	Out.Update(3, sqG(t))
	return bpf.XDPPass
}

func main() {}
