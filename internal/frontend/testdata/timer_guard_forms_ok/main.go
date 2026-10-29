package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Pair struct {
	Lock bpf.SpinLock `schema:"lock"`
	A    uint32       `schema:"a"`
	B    uint32       `schema:"b"`
}

type Win struct {
	T bpf.Timer `schema:"t"`
	N uint64    `schema:"n"` // the callback's count (only the callback writes it — if the program wrote the same field it would be GB028)
	S uint64    `schema:"s"` // record of the program's status
}

var Pairs = bpf.Array[uint32, Pair]{MaxEntries: 1}
var Wins = bpf.Array[uint32, Win]{MaxEntries: 1}

func onFire(w *Win) {
	w.N++
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if w := Wins.Lookup(0); w != nil {
		if w.T.Init() == 0 {
			_ = w.T.SetCallback(onFire)
			_ = w.T.Start(1000)
		}
		st := w.T.Init()
		w.S = uint64(st)
		if 0 == st {
			_ = w.T.Start(2000)
		}
	}
	return bpf.XDPPass
}

func main() {}
