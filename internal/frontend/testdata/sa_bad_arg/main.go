package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func get(p *uint64) uint64 { return *p }

// relay passes a borrowed argument to another subprogram (refused for now — GB013 at the argument).
func relay(p *uint64) uint64 { return get(p) + 1 }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := C.Lookup(0); p != nil {
		Out.Update(0, relay(p))
	}
	return bpf.XDPPass
}

func main() {}
