package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Two userstr_status fields — GB016.
type Ev struct {
	Status int64     `schema:"status" gobpf:"userstr_status"`
	Again  int64     `schema:"again" gobpf:"userstr_status"`
	Tag    uint32    `schema:"tag"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
	_      [4]byte
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	_, _ = Names.OutputStr(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
}

func main() {}
