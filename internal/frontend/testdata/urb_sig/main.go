package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The drain callback must be `func name(r V, ok bool) bool` (a signature without ok stops — a short sample is never read silently).

type Msg struct {
	Kind uint32 `schema:"kind"`
}

var (
	In = bpf.UserRingBuf[Msg]{MaxEntries: 4096}
	N  = bpf.Global[uint64]{}
)

func onMsg(m Msg) bool {
	N.Add(uint64(m.Kind))
	return false
}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = In.Drain(onMsg)
	return bpf.XDPPass
}

func main() {}
