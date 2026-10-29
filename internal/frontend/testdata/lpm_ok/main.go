package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: a 64-bit signed value, a `_` on one side, a constant address, the ASSIGN form.
var T = bpf.LPMTrie4[int64]{MaxEntries: 4}
var Out = bpf.Array[uint32, int64]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	var v int64
	var ok bool
	v, ok = T.Lookup([4]byte{192, 0, 2, 1})
	if ok {
		Out.Update(0, v)
	}
	if _, hit := T.Lookup([4]byte{10, 0, 0, 1}); hit {
		Out.Update(0, 2)
	}
	return bpf.XDPPass
}

func main() {}
