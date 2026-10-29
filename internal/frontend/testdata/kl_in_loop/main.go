package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	S   = bpf.Stack[uint32]{MaxEntries: 4}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	n := uint64(0)
	for i := uint32(0); i < 4; i++ {
		v, _ := S.Pop()
		n += uint64(v)
	}
	Out.Update(0, n)
	return bpf.XDPPass
}

func main() {}
