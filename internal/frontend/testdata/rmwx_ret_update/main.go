package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

// readC carries C[0] in its return value (R).
func readC() uint64 {
	v := uint64(0)
	if p := C.Lookup(0); p != nil {
		v = *p
	}
	return v
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	C.Update(0, readC()+1)
	return bpf.XDPPass
}

func main() {}
