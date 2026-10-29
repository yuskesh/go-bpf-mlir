package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// netfilter ctx reads are only Hook / PF / SkbLen (the range of bpf-mlir's nf.mlir) — there are no methods for other fields.
func onNF(ctx *bpf.NetfilterContext) bpf.NFAction {
	if ctx.Mark() == 1 {
		return bpf.NFDrop
	}
	return bpf.NFAccept
}

func main() {}
