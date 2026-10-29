package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: lwt_in / lwt_out / lwt_xmit — reading len and a packet window (from the IP header), verdicts LWTDrop / LWTOK.

var Out = bpf.Array[uint32, uint64]{MaxEntries: 3}

func onIn(ctx *bpf.LWTInContext) bpf.LWTAction {
	Out.Update(0, uint64(ctx.Len()))
	return bpf.LWTOK
}

func onOut(ctx *bpf.LWTOutContext) bpf.LWTAction {
	if w, ok := ctx.Check(0, 20); ok {
		Out.Update(1, uint64(w.U8(9)))
	}
	return bpf.LWTOK
}

func onXmit(ctx *bpf.LWTXmitContext) bpf.LWTAction {
	if ctx.Len() > 1000 {
		return bpf.LWTDrop
	}
	return bpf.LWTOK
}

func main() {}
