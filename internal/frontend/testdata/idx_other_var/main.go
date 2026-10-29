package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type R struct {
	Arr [8]uint32 `schema:"arr"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	i, j := uint32(3), uint32(4)
	x := uint64(0)
	if p := M.Lookup(0); p != nil {
		if i < uint32(len(p.Arr)) {
			x = uint64(p.Arr[j])
		}
	}
	Out.Update(0, x+uint64(i))
	return bpf.XDPPass
}

func main() {}
