package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Stat = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:sk_msg Stat
func f(ctx *bpf.SKMsgContext) bpf.SKAction {
	return bpf.SKPass
}

func main() {}
