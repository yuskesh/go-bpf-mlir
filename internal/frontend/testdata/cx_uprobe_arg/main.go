package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// UprobeArg inside a callee that takes the context — satisfies the uprobe binary path rule (the in-package fixture cfix),
// so the callee refusal (GB013 — an attach-dependent read) is seen directly.
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func second(ctx *bpf.UprobeContext) uint32 {
	return bpf.UprobeArg[uint32](ctx, 2)
}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(second(ctx)))
}

func main() {}
