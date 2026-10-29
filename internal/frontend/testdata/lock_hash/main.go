package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pair struct {
	Lock bpf.SpinLock `schema:"lock"`
	A    uint32       `schema:"a"`
	B    uint32       `schema:"b"`
}

type Win struct {
	T bpf.Timer `schema:"t"`
	N uint64    `schema:"n"`
}

var Pairs = bpf.Array[uint32, Pair]{MaxEntries: 1}
var Wins = bpf.Array[uint32, Win]{MaxEntries: 1}

var H = bpf.Hash[uint32, Pair]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := H.Lookup(0); p != nil {
		p.A++
	}
	return bpf.XDPPass
}

func main() {}
