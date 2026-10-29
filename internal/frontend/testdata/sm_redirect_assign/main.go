package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

//gobpf:sk_skb Socks
func f(ctx *bpf.SKSKBContext) bpf.SKAction {
	a := Socks.Redirect(ctx, 1, bpf.SKIngress)
	return a
}

func main() {}
