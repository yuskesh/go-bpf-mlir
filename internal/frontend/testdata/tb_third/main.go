package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A third borrow — the depth is at most 2 (GB001).
type Rec struct {
	X uint64 `schema:"x"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}
var B = bpf.Array[uint32, Rec]{MaxEntries: 4}
var C = bpf.Array[uint32, Rec]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(0); p != nil {
		if q := B.Lookup(0); q != nil {
			if r := C.Lookup(0); r != nil {
				r.X = p.X + q.X
			}
		}
	}
	return bpf.XDPPass
}

func main() {}
