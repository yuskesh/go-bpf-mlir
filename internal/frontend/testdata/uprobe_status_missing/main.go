package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Ev has no userstr_status field — OutputStr is GB016 (a failure could not be told from an empty string).
type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	_, _ = Names.OutputStr(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
}

func main() {}
