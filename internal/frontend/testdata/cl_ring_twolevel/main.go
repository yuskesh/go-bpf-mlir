package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Ev struct {
	N uint32 `schema:"n"`
}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func emit(n uint32) bool { return Events.Output(Ev{N: n}) }

func relay(n uint32) bool { return emit(n + 1) }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	for i := uint32(0); i < 4; i++ {
		_ = relay(i)
	}
	Out.Update(0, 1)
	return bpf.XDPPass
}

func main() {}
