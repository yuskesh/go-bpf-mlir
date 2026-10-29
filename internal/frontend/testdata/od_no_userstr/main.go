package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A record with no userstr field — GB016 (same as OutputStr — exactly one string destination is required).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name"`
	_    [4]byte
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	st, _ := Names.OutputStrOrDiscard(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
	Out.Update(0, uint64(st))
}

func main() {}
