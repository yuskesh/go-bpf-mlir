package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	Names.OutputStr(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
}

func main() {}
