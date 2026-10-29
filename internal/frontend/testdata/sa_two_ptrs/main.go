package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// add takes two borrowed arguments (GB013 — at most one).
func add(p *uint64, q *uint64) uint64 { return *p + *q }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := C.Lookup(0); p != nil {
		Out.Update(0, add(p, p))
	}
	return bpf.XDPPass
}

func main() {}
