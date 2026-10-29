package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:lsm socket_create
func f(ctx *bpf.LSMContext) bpf.LSMRet {
	if bpf.KtimeNs() > 0 {
		fam := bpf.LSMArgInt[int32](ctx, 0)
		Out.Update(0, uint64(fam))
	}
	return bpf.LSMAllow
}

func main() {}
