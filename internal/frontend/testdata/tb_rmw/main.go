package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// An RMW of a shared map inside two borrows — q.S = q.S + p.X is a non-atomic read-modify-write of q.S (GB028).
type Rec struct {
	X uint64 `schema:"x"`
}

type Acc struct {
	S uint64 `schema:"s"`
}

var A = bpf.Array[uint32, Rec]{MaxEntries: 4}
var B = bpf.Array[uint32, Acc]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(0); p != nil {
		if q := B.Lookup(0); q != nil {
			q.S = q.S + p.X
		}
	}
	return bpf.XDPPass
}

func main() {}
