package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// OutputStrOrDiscard as a statement (discards st and sent) — GB017 (same as OutputStr).
type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
	_    [4]byte
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	Names.OutputStrOrDiscard(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
}

func main() {}
