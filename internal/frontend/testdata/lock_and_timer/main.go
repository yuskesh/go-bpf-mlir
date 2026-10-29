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

type Both struct {
	Lock bpf.SpinLock `schema:"lock"`
	_    [4]byte
	T    bpf.Timer `schema:"t"`
}

var Bs = bpf.Array[uint32, Both]{MaxEntries: 1}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	return bpf.XDPPass
}

func main() {}
