package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	A uint32 `schema:"a"`
	B uint32 `schema:"b"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

// A double consume — the frontend lets it through and bpf-mlir's ownership check stops it.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	if e, ok := Events.Reserve(); ok {
		e.A = 1
		Events.Submit(e)
		Events.Submit(e)
	}
	return bpf.XDPPass
}

func main() {}
