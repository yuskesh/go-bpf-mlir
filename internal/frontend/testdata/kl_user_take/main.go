package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	Q   = bpf.Queue[uint32]{MaxEntries: 4}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	v, _ := Q.Take()
	Out.Update(0, uint64(v))
	return bpf.XDPPass
}

func main() {}
