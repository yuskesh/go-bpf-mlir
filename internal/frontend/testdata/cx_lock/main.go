package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// WithLock inside a callee that takes the context — bpf-mlir allows spin.region only in the program body (GB026 / GB013).
type Locked struct {
	Lock bpf.SpinLock `schema:"lock"`
	_    [4]byte
	N    uint64 `schema:"n"`
}

var L = bpf.Array[uint32, Locked]{MaxEntries: 1}

func bump(ctx *bpf.XDPContext) uint32 {
	if p := L.Lookup(0); p != nil {
		bpf.WithLock(&p.Lock, func() {
			p.N = p.N + 1
		})
	}
	return 0
}

func P(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = bump(ctx)
	return bpf.XDPPass
}

func main() {}
