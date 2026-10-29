package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:lsm socket_create
func f(ctx *bpf.LSMContext) bpf.LSMRet {
	e := int32(bpf.KtimeNs() & 7)
	return bpf.LSMDeny(e + 1)
}

func main() {}
