package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Writes the userstr field in the event literal — GB016 (OutputStrOrDiscard writes it — same as OutputStr).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
	_    [4]byte
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	st, _ := Names.OutputStrOrDiscard(Ev{Tag: 1, Name: [16]uint8{1}}, bpf.UprobeStr(ctx, 1))
	Out.Update(0, uint64(st))
}

func main() {}
