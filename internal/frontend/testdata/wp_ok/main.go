package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Helpers with one packet window and one borrow argument — from xdp and tc, a checked borrow (borrowed) and an unchecked M.Lookup(k) (maybe_ref),
// both nesting orders (Lookup inside a window, Check inside a Lookup), window writes and borrow reads in an xdp helper, a borrow of an integer value.

type Rule struct {
	Proto uint32 `schema:"proto"`
	Class uint32 `schema:"class"`
}

var Rules = bpf.Array[uint32, Rule]{MaxEntries: 4}
var Base = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Counts = bpf.Array[uint32, uint64]{MaxEntries: 16}

// classify reads a checked borrow (borrowed) and the packet window.
func classify(w bpf.Window, p *Rule) uint32 {
	c := uint32(0)
	if uint32(w.U8(23)) == p.Proto {
		c = p.Class
	}
	return c
}

// orDefault reads an unchecked borrow (maybe_ref — the caller passes M.Lookup(k) directly) and the packet window.
func orDefault(w bpf.Window, p *Rule) uint32 {
	c := uint32(w.U8(0)) & 3
	if p != nil {
		c = p.Class ^ uint32(w.U8(1))
	}
	return c
}

// stamp writes to the packet window (xdp callers only) and reads a borrow (an integer value).
func stamp(w bpf.Window, b *uint64) uint32 {
	w.SetU8(15, uint8(*b))
	return uint32(*b)
}

func xdpProg(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(0); p != nil { // Lookup inside a window
			k = classify(w, p)
		}
		k += orDefault(w, Rules.Lookup(1))
		if b := Base.Lookup(0); b != nil {
			k += stamp(w, b)
		}
	}
	if p := Rules.Lookup(2); p != nil { // Check inside a Lookup
		if w, ok := ctx.Check(0, 24); ok {
			k += classify(w, p)
		}
	}
	Counts.AtomicAdd(k&15, 1)
	return bpf.XDPPass
}

func tcProg(ctx *bpf.TCIngressContext) bpf.TCAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 24); ok {
		if p := Rules.Lookup(3); p != nil {
			k = classify(w, p)
		}
		k += orDefault(w, Rules.Lookup(0))
	}
	Counts.AtomicAdd(k&15, 1)
	return bpf.TCPass
}

func main() {}
