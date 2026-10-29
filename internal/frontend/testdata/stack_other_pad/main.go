package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The stack overflows from a large map value (Big.Update builds the 1 KiB value on the stack), not from the padding — the small padded
// event Ev in the same function is not the cause. generate still names the padding as the likely cause (GB016), with ebpf-compile's text.
type Val struct {
	A [1024]byte `schema:"a"`
}

type Ev struct {
	Seq uint32 `schema:"seq"`
	_   [4]byte
}

var Big = bpf.Array[uint32, Val]{MaxEntries: 1}

var Events = bpf.RingBuf[Ev]{MaxEntries: 4096}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	Big.Update(0, Val{})
	_ = Events.Output(Ev{Seq: 1})
	return bpf.XDPPass
}

func main() {}
