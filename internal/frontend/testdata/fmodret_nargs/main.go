package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The fmod_ret directive needs the function's argument count nargs=<N> (for the retsig check at load time).
//
//gobpf:fmod_ret bpf_modify_return_test
func onModRet(ctx *bpf.FmodRetContext) bpf.FmodRet {
	return 0
}

func main() {}
