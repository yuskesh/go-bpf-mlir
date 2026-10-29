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

var Out = bpf.Array[uint32, uint32]{MaxEntries: 1}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Pairs.Lookup(0); p != nil {
		l := p.Lock
		_ = l
	}
	return bpf.XDPPass
}

func main() {}
