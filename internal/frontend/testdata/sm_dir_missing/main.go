package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

//gobpf:sk_skb Nope
func f(ctx *bpf.SKSKBContext) bpf.SKAction {
	return Socks.Redirect(ctx, 0, bpf.SKIngress)
}

func main() {}
