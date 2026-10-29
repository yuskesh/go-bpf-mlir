package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The lwt context cannot be passed to a subprogram (read it in the program body — pass integers).
func big(ctx *bpf.LWTOutContext) uint32 {
	if ctx.Len() > 1000 {
		return 1
	}
	return 0
}

func onOut(ctx *bpf.LWTOutContext) bpf.LWTAction {
	if big(ctx) == 1 {
		return bpf.LWTDrop
	}
	return bpf.LWTOK
}

func main() {}
