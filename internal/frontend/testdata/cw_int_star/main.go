package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Unchanged rule: `*c = v` through a pointer to an integer map value — refused, as inside a program (integer maps are written with M.Update / M.AtomicAdd).
var C = bpf.Array[uint32, uint64]{MaxEntries: 2}

func putC(c *uint64, v uint64) uint64 {
	*c = v
	return v
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if c := C.Lookup(0); c != nil {
		_ = putC(c, 9)
	}
	return bpf.XDPPass
}

func main() {}
