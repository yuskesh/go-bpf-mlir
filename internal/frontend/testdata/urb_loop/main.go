package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Drain cannot be inside a loop (ebpf.user_ringbuf.drain is not allowed in a bpf-mlir loop body).

type Msg struct {
	Kind uint32 `schema:"kind"`
}

var (
	In = bpf.UserRingBuf[Msg]{MaxEntries: 4096}
	N  = bpf.Global[uint64]{}
)

func onMsg(m Msg, ok bool) bool {
	N.Add(1)
	return false
}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	for i := uint32(0); i < 2; i++ {
		_ = In.Drain(onMsg)
	}
	return bpf.XDPPass
}

func main() {}
