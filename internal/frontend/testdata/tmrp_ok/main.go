package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case for a periodic timer — if, else and two nested levels in the callback, and Start of its own timer (`st :=` and `_ =`).
type Pv struct {
	T     bpf.Timer `schema:"t"`
	Count uint64    `schema:"count"`
	St    int64     `schema:"st"`
	Ok    uint64    `schema:"ok"`
}

var Vals = bpf.Array[uint32, Pv]{MaxEntries: 1}

func tick(v *Pv) {
	c := v.Count + 1
	v.Count = c
	if c < 5 {
		st := v.T.Start(1000)
		v.St = st
		if st == 0 {
			v.Ok++
		}
	} else {
		if c == 7 {
			_ = v.T.Start(2000)
		}
	}
}

func onArm(ctx *bpf.XDPContext) bpf.XDPAction {
	if v := Vals.Lookup(0); v != nil {
		if st := v.T.Init(); st == 0 {
			_ = v.T.SetCallback(tick)
			_ = v.T.Start(1000)
		}
	}
	return bpf.XDPPass
}

func main() {}
