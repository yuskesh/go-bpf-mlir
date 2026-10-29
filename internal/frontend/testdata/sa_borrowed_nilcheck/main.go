package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// safe checks for nil, but every caller passes a checked borrow (GB013 — p is never nil).
func safe(p *uint64) uint64 {
	v := uint64(0)
	if p != nil {
		v = *p
	}
	return v
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := C.Lookup(0); p != nil {
		Out.Update(0, safe(p))
	}
	return bpf.XDPPass
}

func main() {}
