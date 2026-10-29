package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:lsm
func f(ctx *bpf.LSMContext) bpf.LSMRet {
	return bpf.LSMAllow
}

func main() {}
