package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

// addC AtomicAdds its argument to C[0] ((W) — delta).
func addC(d uint64) bool {
	C.AtomicAdd(0, d)
	return true
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	y := uint64(0)
	if q := C.Lookup(0); q != nil {
		y = *q
	}
	_ = addC(y)
	return bpf.XDPPass
}

func main() {}
