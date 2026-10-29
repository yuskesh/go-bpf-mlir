package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var T = bpf.LPMTrie4[uint32]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	T.Update([4]byte{1, 2, 3, 4}, 1)
	return bpf.XDPPass
}

func main() {}
