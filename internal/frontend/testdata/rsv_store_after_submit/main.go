package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	A uint32 `schema:"a"`
	B uint32 `schema:"b"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

// An assignment after the consume.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	if e, ok := Events.Reserve(); ok {
		e.A = 1
		Events.Submit(e)
		e.B = 2
	}
	return bpf.XDPPass
}

func main() {}
