package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// sched_act's mark is write-only (bpf-mlir's ctxaccess.tsv) — there is no read method.
func f(ctx *bpf.TCActContext) bpf.TCActAction {
	Out.Update(0, uint64(ctx.Mark()))
	return bpf.TCActOK
}

func main() {}
