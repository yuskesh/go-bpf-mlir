package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: user_ringbuf Drain with a named callback (sample field reads, ok, an if with a global Add — a branchless select, stop).

type Msg struct {
	Kind uint32 `schema:"kind"`
	Len  uint32 `schema:"len"`
}

var (
	In    = bpf.UserRingBuf[Msg]{MaxEntries: 8192}
	Out   = bpf.Array[uint32, int64]{MaxEntries: 1}
	Bytes = bpf.Global[uint64]{}
	Bad   = bpf.Global[uint64]{}
)

func onMsg(m Msg, ok bool) bool {
	if ok {
		Bytes.Add(uint64(m.Len))
	} else {
		Bad.Add(1)
	}
	return m.Kind == 0
}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, In.Drain(onMsg))
	return bpf.XDPPass
}

func main() {}
