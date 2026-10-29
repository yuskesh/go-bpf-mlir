package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// OutputStrOrDiscard inside a loop — GB018 (ring buffer operations cannot be in a loop body — same as OutputStr).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
	_    [4]byte
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	n := uint64(0)
	for i := uint32(0); i < 2; i++ {
		st, _ := Names.OutputStrOrDiscard(Ev{Tag: i}, bpf.UprobeStr(ctx, 1))
		n += uint64(st)
	}
	Out.Update(0, n)
}

func main() {}
