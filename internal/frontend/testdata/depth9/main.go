package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func F1(x uint32) uint32 { return F2(x) + 1 }

func F2(x uint32) uint32 { return F3(x) + 1 }

func F3(x uint32) uint32 { return F4(x) + 1 }

func F4(x uint32) uint32 { return F5(x) + 1 }

func F5(x uint32) uint32 { return F6(x) + 1 }

func F6(x uint32) uint32 { return F7(x) + 1 }

func F7(x uint32) uint32 { return F8(x) + 1 }

func F8(x uint32) uint32 { return x }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(F1(1)))
	return bpf.XDPPass
}

func main() {}
