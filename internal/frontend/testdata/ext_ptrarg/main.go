package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The replaced function's arguments must be integers only (bpf-mlir's ebpf.ext.arg — a borrowed map value argument cannot be replaced).
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:global
func g(p *uint64) uint64 { return *p + 10 }

func tgt(ctx *bpf.XDPContext) bpf.XDPAction {
	v := uint64(0)
	if p := C.Lookup(0); p != nil {
		v = g(p)
	}
	if v > 5 {
		return bpf.XDPDrop
	}
	return bpf.XDPPass
}

//gobpf:ext tgt g
func rep(ctx *bpf.ExtContext) uint64 {
	return 100
}

func main() {}
