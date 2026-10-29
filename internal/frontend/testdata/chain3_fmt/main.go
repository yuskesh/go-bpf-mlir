package main

import (
	"fmt"

	"github.com/yuskesh/go-bpf-mlir/bpf"
)

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

func C(x uint32) uint32 {
	fmt.Println(x)
	return x + 1
}

func B(x uint32) uint32 { return C(x) * 2 }

func A(x uint32) uint32 { return B(x) + 3 }

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Counts.Update(0, uint64(A(1)))
	return bpf.XDPPass
}

func main() {}
