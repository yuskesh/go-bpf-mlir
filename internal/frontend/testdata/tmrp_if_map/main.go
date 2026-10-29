package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A map use inside an if in the callback — GB026 (the existing message).
type Pv struct {
	T     bpf.Timer `schema:"t"`
	Count uint64    `schema:"count"`
}

var Vals = bpf.Array[uint32, Pv]{MaxEntries: 1}

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func tick(v *Pv) {
	v.Count++
	if v.Count < 3 {
		Out.Update(0, v.Count)
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
