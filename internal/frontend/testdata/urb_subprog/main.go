package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Drain is program body only (it stops inside a subprogram — bpf-mlir's ebpf.user_ringbuf.drain is a program-body op).

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

func drainAll() int64 {
	return In.Drain(onMsg)
}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	if drainAll() > 0 {
		return bpf.XDPDrop
	}
	return bpf.XDPPass
}

func main() {}
