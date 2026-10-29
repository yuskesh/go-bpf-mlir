package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var K = bpf.Array[uint32, uint32]{MaxEntries: 1}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	k := uint32(1)
	if c := K.Lookup(0); c != nil {
		k = *c & 3
	}
	if p := C.Lookup(0); p != nil {
		C.Update(k, *p+1)
	}
	return bpf.XDPPass
}

func main() {}
