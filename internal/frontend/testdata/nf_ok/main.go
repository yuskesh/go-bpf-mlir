package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: netfilter — reading state's hook / pf and skb's len (kfields of kernel pointers), verdicts NFDrop / NFAccept.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func onNF(ctx *bpf.NetfilterContext) bpf.NFAction {
	Out.Update(0, uint64(ctx.Hook())<<8|uint64(ctx.PF()))
	if ctx.SkbLen() > 1000 {
		return bpf.NFDrop
	}
	return bpf.NFAccept
}

func main() {}
