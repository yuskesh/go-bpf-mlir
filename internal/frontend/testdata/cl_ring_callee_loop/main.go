package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	N uint32 `schema:"n"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func emit(n uint32) bool { return Events.Output(Ev{N: n}) }

func burst(n uint32) uint32 {
	var c uint32
	for i := uint32(0); i < 4; i++ {
		if emit(n + i) {
			c++
		}
	}
	return c
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, uint64(burst(1)))
	return bpf.XDPPass
}

func main() {}
