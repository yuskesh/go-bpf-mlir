package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Ev struct {
	Tag    uint32    `schema:"tag"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	_      [4]byte
	Status int64 `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

// Positive case: integers and strings in the C fixture, an //export C entry in the cgo fixture, a `_` on one side.
//
//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	st, _ := Names.OutputStr(Ev{Tag: bpf.UprobeArg[uint32](ctx, 2)}, bpf.UprobeStr(ctx, 1))
	Out.Update(0, uint64(st))
}

//gobpf:uprobe cgofix.bin SumArgs
func g(ctx *bpf.UprobeContext) {
	Out.Update(0, uint64(bpf.UprobeArg[int64](ctx, 1)+int64(bpf.UprobeArg[int32](ctx, 3))))
}

func main() {}
