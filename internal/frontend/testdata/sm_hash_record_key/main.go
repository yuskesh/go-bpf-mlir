package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type K struct {
	A uint32 `schema:"a"`
}

var Hash = bpf.SockHash[K]{MaxEntries: 2}

//gobpf:sk_skb Hash
func f(ctx *bpf.SKSKBContext) bpf.SKAction {
	return bpf.SKPass
}

func main() {}
