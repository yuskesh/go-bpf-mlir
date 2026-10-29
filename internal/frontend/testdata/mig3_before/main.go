package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Migration example 3 (v0.4.0 release notes — before): reads a value at the same key of the same map and writes it back with Update (GB028).
var C = bpf.Array[uint32, uint64]{MaxEntries: 4}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := C.Lookup(0); p != nil {
		C.Update(0, *p+1)
	}
	return bpf.XDPPass
}

func main() {}
