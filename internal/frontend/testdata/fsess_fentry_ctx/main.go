package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

// IsReturn is a FsessionContext method — the fentry ctx has none (type check).
//
//gobpf:fentry bpf_fentry_test1
func f(ctx *bpf.FentryContext) {
	if ctx.IsReturn() {
		Out.AtomicAdd(0, 1)
	}
}

func main() {}
