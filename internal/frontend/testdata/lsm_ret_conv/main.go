package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:lsm socket_create
func f(ctx *bpf.LSMContext) bpf.LSMRet {
	fam := bpf.LSMArgInt[int32](ctx, 0)
	return bpf.LSMRet(-fam)
}

func main() {}
