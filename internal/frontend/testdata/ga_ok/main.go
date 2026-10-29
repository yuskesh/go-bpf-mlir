package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Controls: the delta of G.Add is another global's Load, a constant, a packet value, a map value, or Config — all accepted. Also another global across a helper.
var G = bpf.Global[uint64]{}
var H = bpf.Global[uint64]{}
var Step = bpf.Config[uint64]{}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func bump(d uint64) uint64 {
	G.Add(d)
	return d
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	G.Add(H.Load() & 0xFF)
	v := H.Load() + 1
	G.Add(v)
	G.Add(3)
	G.Add(Step.Value())
	if c := C.Lookup(0); c != nil {
		G.Add(*c)
	}
	if w, ok := ctx.Check(0, 14); ok {
		G.Add(uint64(w.U8(13)))
	}
	_ = bump(H.Load())
	H.Add(G.Load() & 1)
	return bpf.XDPPass
}

func main() {}
