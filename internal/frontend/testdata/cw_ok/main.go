package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Accepted shapes and controls: writes through a callee's borrowed argument — ++ / += on a per-CPU map, bpf.AtomicAdd (constant or packet delta),
// stores of constants or values from another map or a different constant key, a store inside a maybe_ref branch, a store in a window-and-borrow helper.
type Rec struct {
	N uint64 `schema:"n"`
	M uint64 `schema:"m"`
}

type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}
var PC = bpf.PerCPUArray[uint32, Rec]{MaxEntries: 4}
var S = bpf.Hash[uint32, Rec]{MaxEntries: 16}
var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}

// bumpPC is an RMW of a per-CPU value (accepted — no other CPU writes the same value).
func bumpPC(p *Rec, d uint64) uint64 {
	p.N++
	p.M += d
	return p.N
}

// addN is an atomic add (the delta is the caller's constant or packet value).
func addN(p *Rec, d uint64) uint64 {
	bpf.AtomicAdd(&p.N, d)
	return d
}

// set writes its argument (the caller passes a value from another map or a different constant key).
func set(p *Rec, n uint64) uint64 {
	p.N = n
	return n
}

// setM writes a constant.
func setM(p *Rec) uint64 {
	p.M = 7
	return 7
}

// fill takes an unchecked M.Lookup(k) and writes inside a branch.
func fill(p *Rec) uint64 {
	r := uint64(0)
	if p != nil {
		p.M = 1
		r = 1
	}
	return r
}

// learn takes a packet window and a borrow, and writes a packet value to the borrow.
func learn(w bpf.Window, p *Rule) uint32 {
	p.Proto = uint32(w.U8(23))
	return p.Class
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := PC.Lookup(0); p != nil {
		_ = bumpPC(p, 3)
	}
	if p := R.Lookup(0); p != nil {
		_ = addN(p, 1)
		_ = setM(p)
		if q := S.Lookup(5); q != nil {
			_ = set(p, q.M)
		}
		if q := R.Lookup(1); q != nil {
			_ = set(p, q.N)
		}
	}
	_ = fill(R.Lookup(3))
	return bpf.XDPPass
}

func Pkt(ctx *bpf.XDPContext) bpf.XDPAction {
	if w, ok := ctx.Check(0, 24); ok {
		if p := R.Lookup(2); p != nil {
			_ = addN(p, uint64(w.U8(20)))
		}
		if p := Rules.Lookup(0); p != nil {
			_ = learn(w, p)
		}
	}
	return bpf.XDPPass
}

func main() {}
