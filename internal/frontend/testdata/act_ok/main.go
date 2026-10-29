package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: sched_act's three verdicts, reading len, writing mark, and a packet window.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 2}

func act(ctx *bpf.TCActContext) bpf.TCActAction {
	if w, ok := ctx.Check(23, 1); ok {
		Out.Update(0, uint64(w.U8(0)))
	}
	ctx.SetMark(ctx.Len())
	if ctx.Len() > 1000 {
		return bpf.TCActShot
	}
	return bpf.TCActOK
}

func pipe(ctx *bpf.TCActContext) bpf.TCActAction {
	return bpf.TCActPipe
}

func main() {}
