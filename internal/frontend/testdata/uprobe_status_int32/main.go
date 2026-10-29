package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The userstr_status field is int32 — only int64 is allowed (read_str's status type) — GB016.
type Ev struct {
	Status int32     `schema:"status" gobpf:"userstr_status"`
	Tag    uint32    `schema:"tag"`
	Name   [16]uint8 `schema:"name" gobpf:"userstr"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	_, _ = Names.OutputStr(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
}

func main() {}
