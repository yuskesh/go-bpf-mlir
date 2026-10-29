package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var T = bpf.LPMTrie4[uint16]{MaxEntries: 4}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	return bpf.XDPPass
}

func main() {}
