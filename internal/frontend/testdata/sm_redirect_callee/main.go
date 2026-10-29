package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

func pick(ctx *bpf.SKSKBContext) bpf.SKAction {
	return Socks.Redirect(ctx, 1, bpf.SKIngress)
}

//gobpf:sk_skb Socks
func f(ctx *bpf.SKSKBContext) bpf.SKAction {
	return pick(ctx)
}

func main() {}
