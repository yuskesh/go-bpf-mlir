package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stat = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:sk_skb Stat
func f(ctx *bpf.SKSKBContext) bpf.SKAction {
	return bpf.SKPass
}

func main() {}
