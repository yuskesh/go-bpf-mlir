package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var (
	Q   = bpf.Queue[uint32]{MaxEntries: 4}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	fl := bpf.PushAny
	if bpf.KtimeNs() > 0 {
		fl = bpf.PushExist
	}
	st := Q.Push(1, fl)
	Out.Update(0, uint64(st))
	return bpf.XDPPass
}

func main() {}
