package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	N uint32 `schema:"n"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func emit(n uint32) bool { return Events.Output(Ev{N: n}) }

func sq(x uint32) uint32 { return x * x }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	var s uint32
	for i := uint32(0); i < 4; i++ {
		s += sq(i)
	}
	_ = emit(s)
	Out.Update(0, uint64(s))
	return bpf.XDPPass
}

func main() {}
