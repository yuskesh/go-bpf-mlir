package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix no_such_function
func f(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int64](ctx, 1)))
}

func main() {}
