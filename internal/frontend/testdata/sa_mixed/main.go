package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 4}
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func get(p *uint64) uint64 { return *p }

// Calls get both with checked borrows (2 sites) and an unchecked Lookup (1 site) (GB013 — names every site).
func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	t := uint64(0)
	if p := C.Lookup(0); p != nil {
		t = get(p)
	}
	if q := C.Lookup(1); q != nil {
		t += get(q)
	}
	Out.Update(0, t+get(C.Lookup(2)))
	return bpf.XDPPass
}

func main() {}
