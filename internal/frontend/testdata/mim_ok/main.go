package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	A   = bpf.ArrayOfMaps[uint32, uint64]{MaxEntries: 2, Inner: bpf.InnerSpec{Kind: bpf.InnerArray, MaxEntries: 4}}
	H   = bpf.HashOfMaps[uint32, uint32, uint32]{MaxEntries: 8, Inner: bpf.InnerSpec{Kind: bpf.InnerLRUHash, MaxEntries: 16}}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 2}
)

// Positive case: array_of_maps and hash_of_maps, inner array / lru_hash, inner Lookup / Update / AtomicAdd, an outer else branch.

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint64(0)
	if m := A.Lookup(1); m != nil {
		if p := m.Lookup(3); p != nil {
			x = *p
		}
		m.AtomicAdd(0, 1)
	} else {
		x = 9
	}
	if m := H.Lookup(uint32(x)); m != nil {
		m.Update(5, 6)
	}
	Out.Update(0, x)
	return bpf.XDPPass
}

func main() {}
