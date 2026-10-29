package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

// putC writes its argument to C[0] (W).
func putC(v uint64) bool {
	C.Update(0, v)
	return true
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	y := uint64(0)
	if q := C.Lookup(0); q != nil {
		y = *q
	}
	_ = putC(y + 1)
	return bpf.XDPPass
}

func main() {}
