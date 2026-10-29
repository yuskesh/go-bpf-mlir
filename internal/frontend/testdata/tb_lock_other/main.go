package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Reads another borrow inside a WithLock region — the region may touch only the lock's record (GB026, the current rule).
type Locked struct {
	Lock bpf.SpinLock `schema:"lock"`
	_    [4]byte
	N    uint64 `schema:"n"`
}

type Rec struct {
	X uint64 `schema:"x"`
}

var L = bpf.Array[uint32, Locked]{MaxEntries: 4}
var B = bpf.Array[uint32, Rec]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := L.Lookup(0); p != nil {
		if q := B.Lookup(0); q != nil {
			bpf.WithLock(&p.Lock, func() {
				p.N = q.X
			})
		}
	}
	return bpf.XDPPass
}

func main() {}
