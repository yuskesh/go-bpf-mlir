package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	A uint32 `schema:"a"`
	B uint32 `schema:"b"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

// One arm misses it — there is no consume on the path where A is 0.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	a := uint32(0)
	if w, ok := ctx.Check(0, 1); ok {
		a = uint32(w.U8(0))
	}
	if e, ok := Events.Reserve(); ok {
		e.A = a
		if a != 0 {
			Events.Submit(e)
		}
	}
	return bpf.XDPPass
}

func main() {}
