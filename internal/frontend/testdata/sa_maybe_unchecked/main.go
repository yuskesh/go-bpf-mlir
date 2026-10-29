package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// read reads p, passed unchecked, outside a nil check (GB005).
func read(p *uint64) uint64 { return *p + 1 }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, read(C.Lookup(0)))
	return bpf.XDPPass
}

func main() {}
