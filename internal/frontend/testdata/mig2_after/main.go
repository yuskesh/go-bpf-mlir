package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Migration example 2 (v0.4.0 release notes — after): a bpf.PerCPUArray counting into per-CPU slots (no two CPUs write the same slot at once — += is correct).
// The user side sums the per-CPU values from PerProto.GetPerCPU(k).
type Tally struct {
	Packets uint64 `schema:"packets"`
	Bytes   uint64 `schema:"bytes"`
}

var PerProto = bpf.PerCPUArray[uint32, Tally]{MaxEntries: 4}

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
