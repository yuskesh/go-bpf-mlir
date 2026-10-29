package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Init inside the callback — GB026.
type Pv struct {
	T     bpf.Timer `schema:"t"`
	Count uint64    `schema:"count"`
}

var Vals = bpf.Array[uint32, Pv]{MaxEntries: 1}

func tick(v *Pv) {
	v.Count++
	_ = v.T.Init()
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
