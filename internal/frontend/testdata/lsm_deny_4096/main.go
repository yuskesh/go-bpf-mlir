package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:lsm socket_create
func f(ctx *bpf.LSMContext) bpf.LSMRet {
	if bpf.KtimeNs() > 0 {
		return bpf.LSMDeny(4096)
	}
	return bpf.LSMAllow
}

func main() {}
