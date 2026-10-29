package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:lsm socket_create
func f(ctx *bpf.LSMContext) bpf.LSMRet {
	r := bpf.LSMDeny(1)
	Out.Update(0, uint64(r))
	return bpf.LSMAllow
}

func main() {}
