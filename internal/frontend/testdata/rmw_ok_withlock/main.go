package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Tally struct {
	Lock bpf.SpinLock `schema:"lock"`
	_    [4]byte
	N    uint64 `schema:"n"`
	B    uint64 `schema:"b"`
}

var T = bpf.Array[uint32, Tally]{MaxEntries: 1}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := T.Lookup(0); p != nil {
		bpf.WithLock(&p.Lock, func() {
			p.N++
			p.B += p.N
		})
	}
	return bpf.XDPPass
}

func main() {}
