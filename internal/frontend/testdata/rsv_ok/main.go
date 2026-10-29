package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: reserve, per-field writes, a whole-record write, conditional submit / discard, the absent arm.

type Ev struct {
	A uint32 `schema:"a"`
	B uint32 `schema:"b"`
	C uint64 `schema:"c"`
}

var (
	Events = bpf.RingBuf[Ev]{MaxEntries: 4096}
	Out    = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	a := uint32(0)
	if w, ok := ctx.Check(0, 1); ok {
		a = uint32(w.U8(0))
	}
	if e, ok := Events.Reserve(); ok {
		e.A = a
		e.C = 7
		if a > 3 {
			Events.Discard(e)
		} else {
			Events.Submit(e)
		}
	} else {
		Out.AtomicAdd(0, 1)
	}
	if e, ok := Events.Reserve(); ok {
		*e = Ev{A: 1, B: a, C: 2}
		Events.Submit(e)
	}
	return bpf.XDPPass
}

func main() {}
