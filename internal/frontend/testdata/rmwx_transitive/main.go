package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

// readC carries C[0] in its return value, and relay returns readC's value unchanged (a callee's callee — transitive).
func readC() uint64 {
	v := uint64(0)
	if p := C.Lookup(0); p != nil {
		v = *p
	}
	return v
}

func relay() uint64 { return readC() + 0 }

// putC writes its argument to C[0], and store passes its argument to putC (transitive through arguments).
func putC(v uint64) bool {
	C.Update(0, v)
	return true
}

func store(v uint64) bool { return putC(v) }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = store(relay() + 1)
	return bpf.XDPPass
}

func main() {}
