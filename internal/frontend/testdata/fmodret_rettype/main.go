package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// fmod_ret returns bpf.FmodRet (lsm's LSMRet is a type error).
//
//gobpf:fmod_ret bpf_modify_return_test nargs=2
func onModRet(ctx *bpf.FmodRetContext) bpf.FmodRet {
	return bpf.LSMAllow
}

func main() {}
