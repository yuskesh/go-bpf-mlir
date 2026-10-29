package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Socket struct {
	_    bpf.Kernel `kernel:"socket"`
	Type int16      `kernel:"type"`
}

//gobpf:lsm socket_post_create
func f(ctx *bpf.LSMContext) bpf.LSMRet {
	p := bpf.LSMArg[Socket](ctx, 0)
	Out.Update(0, uint64(p.Type))
	return bpf.LSMAllow
}

func main() {}
