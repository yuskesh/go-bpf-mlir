package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Event struct {
	Seq uint64 `schema:"seq"`
}

var Counts = bpf.Array[uint32, uint64]{MaxEntries: 2}

var Events = bpf.RingBuf[Event]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	x := uint64(0)
	for i := range uint32(64) {
		x = x*3 + 1
		x = x*3 + 2
		x = x*3 + 3
		x = x*3 + 4
		x = x*3 + 5
		x = x*3 + 6
		x = x*3 + 7
		x = x*3 + 8
		x = x*3 + 9
		x = x*3 + 10
		x = x*3 + 11
		x = x*3 + 12
		x = x*3 + 13
		x = x*3 + 14
		x = x*3 + 15
		x = x*3 + 16
		x = x*3 + 17
		x = x*3 + 18
		x = x*3 + 19
		x = x*3 + 20
		x = x*3 + 21
		x = x*3 + 22
		x = x*3 + 23
		x = x*3 + 24
		x = x*3 + 25
		x = x*3 + 26
		x = x*3 + 27
		x = x*3 + 28
		x = x*3 + 29
		x = x*3 + 30
		x += uint64(i)
	}
	Counts.Update(0, x)
	return bpf.XDPPass
}

func main() {}
