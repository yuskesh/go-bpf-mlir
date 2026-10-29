package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The netfilter context cannot be passed to a subprogram (read it in the program body — pass integers).
func big(ctx *bpf.NetfilterContext) uint32 {
	if ctx.SkbLen() > 1000 {
		return 1
	}
	return 0
}

func onNF(ctx *bpf.NetfilterContext) bpf.NFAction {
	if big(ctx) == 1 {
		return bpf.NFDrop
	}
	return bpf.NFAccept
}

func main() {}
