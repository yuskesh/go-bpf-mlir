package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Migration example 2 (v0.4.0 release notes — before): ++ and += on an aggregate record in a shared Array (GB028).
type Tally struct {
	Packets uint64 `schema:"packets"`
	Bytes   uint64 `schema:"bytes"`
}

var PerProto = bpf.Array[uint32, Tally]{MaxEntries: 4}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	n := uint64(0)
	if w, ok := ctx.Check(0, 14); ok {
		n = uint64(w.BE16(12))
	}
	if p := PerProto.Lookup(0); p != nil {
		p.Packets++
		p.Bytes += n
	}
	return bpf.XDPPass
}

func main() {}
