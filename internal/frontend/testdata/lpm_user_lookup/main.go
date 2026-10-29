package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var T = bpf.LPMTrie4[uint32]{MaxEntries: 4}
var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	if _, ok := T.Lookup([4]byte{1, 2, 3, 4}); ok {
		Out.Update(0, 1)
	}
	return bpf.XDPPass
}

func main() {
	_, _ = T.Lookup([4]byte{1, 2, 3, 4})
}
