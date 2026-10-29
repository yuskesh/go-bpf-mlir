package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	N uint32 `schema:"n"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func leaf(n uint32) uint32 {
	var s uint32
	for j := uint32(0); j < 2; j++ {
		for k := uint32(0); k < 2; k++ {
			s += j * k * n
		}
	}
	return s
}

func mid(n uint32) uint32 {
	var s uint32
	for i := uint32(0); i < 2; i++ {
		s += leaf(n + i)
	}
	return s
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, uint64(mid(1)))
	return bpf.XDPPass
}

func main() {}
