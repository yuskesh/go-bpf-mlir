package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// OutputStrOrDiscard — an event whose read failed (st < 0) is discarded, others are submitted. Both a record without a status field (Plain) and one
// with it (WithStatus — written when present).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

type Plain struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
	_    [4]byte
}

type WithStatus struct {
	Tag    uint32    `schema:"tag"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	_      [4]byte
	Status int64 `schema:"status" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Plain]{MaxEntries: 4096}
var Full = bpf.RingBuf[WithStatus]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	st, sent := Names.OutputStrOrDiscard(Plain{Tag: bpf.UprobeArg[uint32](ctx, 2)}, bpf.UprobeStr(ctx, 1))
	Out.Update(0, uint64(st))
	if sent {
		Out.AtomicAdd(1, 1)
	}
}

//gobpf:uprobe cfix greet
func g(ctx *bpf.UprobeContext) {
	st, _ := Full.OutputStrOrDiscard(WithStatus{Tag: 7}, bpf.UprobeStr(ctx, 1))
	Out.Update(2, uint64(st))
}

func main() {}
