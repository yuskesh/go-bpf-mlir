package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A record with two status fields — OutputStrOrDiscard does not need a status field, but allows at most one (GB016).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

type Ev struct {
	Tag  uint32    `schema:"tag"`
	Name [16]uint8 `schema:"name" gobpf:"userstr"`
	_    [4]byte
	S1   int64 `schema:"s1" gobpf:"userstr_status"`
	S2   int64 `schema:"s2" gobpf:"userstr_status"`
}

var Names = bpf.RingBuf[Ev]{MaxEntries: 4096}

//gobpf:uprobe cfix greet
func f(ctx *bpf.UprobeContext) {
	st, _ := Names.OutputStrOrDiscard(Ev{Tag: 1}, bpf.UprobeStr(ctx, 1))
	Out.Update(0, uint64(st))
}

func main() {}
