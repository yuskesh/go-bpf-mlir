package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The drain callback cannot use maps (bpf-mlir's ebpf.user_ringbuf.callback allows only arithmetic, sample reads, globals and ktime).

type Msg struct {
	Kind uint32 `schema:"kind"`
}

var (
	In  = bpf.UserRingBuf[Msg]{MaxEntries: 4096}
	Out = bpf.Array[uint32, uint64]{MaxEntries: 1}
)

func onMsg(m Msg, ok bool) bool {
	Out.Update(0, uint64(m.Kind))
	return false
}

func onXDP(ctx *bpf.XDPContext) bpf.XDPAction {
	_ = In.Drain(onMsg)
	return bpf.XDPPass
}

func main() {}
