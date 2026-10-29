package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type R struct {
	Arr [8]uint32 `schema:"arr"`
}

var M = bpf.Array[uint32, R]{MaxEntries: 1}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint64(0)
	for k := range uint32(9) {
		if p := M.Lookup(0); p != nil {
			x += uint64(p.Arr[k])
		}
	}
	Out.Update(0, x)
	return bpf.XDPPass
}

func main() {}
