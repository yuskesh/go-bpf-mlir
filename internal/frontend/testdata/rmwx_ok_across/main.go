package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	N uint64 `schema:"n"`
	A uint64 `schema:"a"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var D = bpf.Array[uint32, uint64]{MaxEntries: 4}
var P = bpf.PerCPUArray[uint32, uint64]{MaxEntries: 1}

// Accepted controls: another map, a different constant key, per-CPU, a return value not derived from a map.

func readC0() uint64 {
	v := uint64(0)
	if p := C.Lookup(0); p != nil {
		v = *p
	}
	return v
}

func readP() uint64 {
	v := uint64(0)
	if p := P.Lookup(0); p != nil {
		v = *p
	}
	return v
}

func sq(x uint64) uint64 { return x * x }

func putC1(v uint64) bool {
	C.Update(1, v)
	return true
}

func writeA(v uint64) bool {
	ok := false
	if p := R.Lookup(0); p != nil {
		p.A = v
		ok = true
	}
	return ok
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	D.Update(0, readC0()+1) // another map
	C.Update(2, readC0()+1) // a different constant key
	_ = putC1(readC0())     // the argument goes to another constant key
	P.Update(0, readP()+1)  // per-CPU
	C.Update(3, sq(5))      // a return value not derived from a map
	n := uint64(0)
	if p := R.Lookup(0); p != nil {
		n = p.N
	}
	_ = writeA(n) // to another field of the same record
	return bpf.XDPPass
}

func main() {}
