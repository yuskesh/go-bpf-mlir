package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Two borrows of the same map with variable keys — they may point at the same value (GB029).
type Rec struct {
	X uint64 `schema:"x"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(0)
	if w, ok := ctx.Check(0, 14); ok {
		k = uint32(w.U8(0)) & 3
	}
	if p := A.Lookup(0); p != nil {
		if q := A.Lookup(k); q != nil {
			q.X = p.X
		}
	}
	return bpf.XDPPass
}

func main() {}
