package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Key struct {
	A uint32 `schema:"a"`
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

var H = bpf.Hash[Key, uint64]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = H.Insert(Key{A: 1}, 1)
	if st := H.Delete(Key{A: 1}); st == -bpf.ENOENT {
		Counts.AtomicAdd(1, 1)
	}
	return bpf.XDPPass
}

func main() {}
