package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	N uint32 `schema:"n"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func inner(n uint32) uint32 {
	var s uint32
	for j := uint32(0); j < 16; j++ {
		s += j * n
	}
	return s
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	var t uint32
	for i := uint32(0); i < 4; i++ {
		t += inner(i)
	}
	Out.Update(0, uint64(t))
	return bpf.XDPPass
}

func main() {}
