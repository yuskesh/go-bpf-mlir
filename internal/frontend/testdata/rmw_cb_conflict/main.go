package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Win struct {
	T     bpf.Timer `schema:"t"`
	Fired uint64    `schema:"fired"`
	Seen  uint64    `schema:"seen"`
}

var Wins = bpf.Array[uint32, Win]{MaxEntries: 1}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func onFire(w *Win) {
	w.Fired++
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if w := Wins.Lookup(0); w != nil {
		if st := w.T.Init(); st == 0 {
			_ = w.T.SetCallback(onFire)
			_ = w.T.Start(1000)
		}
		Out.Update(0, w.Fired)
		w.Fired = 0
	}
	return bpf.XDPPass
}

func main() {}
