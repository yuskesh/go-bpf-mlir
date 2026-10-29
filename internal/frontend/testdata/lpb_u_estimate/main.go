package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Acc = bpf.Array[uint32, uint64]{MaxEntries: 8}

// Control: the same body as onLoop in internal/difftest/loopbe without a directive ((U) unrolling) — the estimate exceeds 4096 and stops.
func f(ctx *bpf.XDPContext) bpf.XDPAction {
	for i := uint32(0); i < 64; i++ {
		Acc.AtomicAdd((i+1)&7, 1)
		Acc.AtomicAdd((i+2)&7, 2)
		Acc.AtomicAdd((i+3)&7, 3)
		Acc.AtomicAdd((i+4)&7, 4)
		Acc.AtomicAdd((i+5)&7, 5)
		Acc.AtomicAdd((i+6)&7, 6)
		Acc.AtomicAdd((i+7)&7, 7)
		Acc.AtomicAdd((i+8)&7, 8)
		Acc.AtomicAdd((i+9)&7, 9)
		Acc.AtomicAdd((i+10)&7, 10)
		Acc.AtomicAdd((i+11)&7, 11)
		Acc.AtomicAdd((i+12)&7, 12)
	}
	return bpf.XDPPass
}

func main() {}
