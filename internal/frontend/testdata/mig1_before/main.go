package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Migration example 1 (v0.4.0 release notes — before): `+=` on a counter in a shared Array (loses counts across CPUs — GB028).
type Stats struct {
	Packets uint64 `schema:"packets"`
}

var Counts = bpf.Array[uint32, Stats]{MaxEntries: 1}

func Count(ctx *bpf.XDPContext) bpf.XDPAction {
	if p := Counts.Lookup(0); p != nil {
		p.Packets += 1
	}
	return bpf.XDPPass
}

func main() {}
