package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var M = bpf.Hash[uint32, uint64]{MaxEntries: 1073741823}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = M.Update(1, 2)
	return bpf.XDPPass
}

func main() {}
