package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Writes the userstr_status field in the literal — OutputStr writes it, so GB016.
type Ev struct {
	Status int64     `schema:"status" gobpf:"userstr_status"`
	Tag    uint32    `schema:"tag"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	_      [4]byte
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	_, _ = Names.OutputStr(Ev{Tag: 1, Status: 7}, bpf.UprobeStr(ctx, 1))
}

func main() {}
