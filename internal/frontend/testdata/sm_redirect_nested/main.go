package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

//gobpf:sk_skb Socks
func f(ctx *bpf.SKSKBContext) bpf.SKAction {
	if ctx.Len() == 5 {
		return bpf.SKDrop
	}
	return Socks.RedirectIf(ctx, ctx.Len() == 7, 1, bpf.SKIngress, bpf.SKPass)
}

func main() {}
