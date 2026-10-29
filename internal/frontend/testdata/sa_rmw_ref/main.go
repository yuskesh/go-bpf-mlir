package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Rec struct {
	A uint64 `schema:"a"`
	B uint64 `schema:"b"`
}

var R = bpf.Array[uint32, Rec]{MaxEntries: 4}

// readA reads and returns a field of a borrowed argument — if the caller writes it back to the same field it is a non-atomic RMW (GB028).
func readA(p *Rec) uint64 { return p.A }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := R.Lookup(0); p != nil {
		p.A = readA(p) + 1
	}
	return bpf.XDPPass
}

func main() {}
