package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The fmod_ret context cannot be passed to a subprogram (read arguments at the top level of the program body — pass integers).
func pick(ctx *bpf.FmodRetContext) uint32 {
	return 1
}

//gobpf:fmod_ret bpf_modify_return_test nargs=2
func onModRet(ctx *bpf.FmodRetContext) bpf.FmodRet {
	if pick(ctx) == 1 {
		return 7
	}
	return 0
}

func main() {}
