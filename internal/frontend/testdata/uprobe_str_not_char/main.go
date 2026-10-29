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

//gobpf:uprobe cfix sum_args
func f(ctx *bpf.UprobeContext) {
	_, _ = Names.OutputStr(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
}

func main() {}
