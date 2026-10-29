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

func onFire(w *Win) {
	w.N++
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if w := Wins.Lookup(0); w != nil {
		st := w.T.Init()
		st = 0
		if st == 0 {
			_ = w.T.SetCallback(onFire)
		}
	}
	return bpf.XDPPass
}

func main() {}
