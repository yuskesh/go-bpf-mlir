package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The drain callback cannot branch — an if may contain only bpf.Global Add (lowered as a branchless select), and early returns are not allowed.

type Msg struct {
	Kind uint32 `schema:"kind"`
}

var (
	In = bpf.UserRingBuf[Msg]{MaxEntries: 4096}
	N  = bpf.Global[uint64]{}
)

func onMsg(m Msg, ok bool) bool {
	if !ok {
		return true
	}
	N.Add(uint64(m.Kind))
	return false
}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = In.Drain(onMsg)
	return bpf.XDPPass
}

func main() {}
