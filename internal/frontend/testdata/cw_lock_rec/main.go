package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Unchanged rule: a helper that takes a lock record — lock / timer records are never borrowed arguments (bpf-mlir also refuses writes to a lock field).
type Acc struct {
	Lock bpf.SpinLock `schema:"lock"`
	_    [4]byte
	N    uint64 `schema:"n"`
}

var A = bpf.Array[uint32, Acc]{MaxEntries: 1}

func setN(p *Acc) uint64 {
	p.N = 1
	return 0
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := A.Lookup(0); p != nil {
		_ = setN(p)
	}
	return bpf.XDPPass
}

func main() {}
