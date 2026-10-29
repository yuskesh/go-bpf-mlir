package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Socks = bpf.SockMap{MaxEntries: 2}

//gobpf:sk_skb Socks
func f(ctx *bpf.SKSKBContext) bpf.SKAction {
	Socks.Set(0, 3)
	return bpf.SKPass
}

func main() {}
