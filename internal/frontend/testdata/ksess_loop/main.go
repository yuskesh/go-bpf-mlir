package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Session ops cannot be inside a loop (same as fsession — not among the ops bpf-mlir allows in a loop body).

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:kprobe_session bpf_fentry_test1
func onSess(ctx *bpf.KprobeSessionContext) bpf.KprobeSessionRet {
	for i := uint32(0); i < 2; i++ {
		Out.Update(0, ctx.Cookie())
	}
	return bpf.KprobeSessionRun
}

func main() {}
