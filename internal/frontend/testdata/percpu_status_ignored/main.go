package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var H = bpf.PerCPUHash[uint32, uint64]{MaxEntries: 16}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	H.Insert(1, 2)
	return bpf.XDPPass
}

func main() {}
