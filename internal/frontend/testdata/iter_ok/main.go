package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// Positive case: iter (bpf_map_elem) — SeqNum, the Seq check, SeqFile.Write's record and status.

type Line struct {
	Seq uint64 `schema:"seq"`
	Tag uint64 `schema:"tag"`
}

var (
	Elems = bpf.Array[uint32, uint64]{MaxEntries: 6}
	Out   = bpf.Array[uint32, uint64]{MaxEntries: 2}
)

//gobpf:iter bpf_map_elem Elems
func dump(ctx *bpf.IterContext) {
	Out.AtomicAdd(0, 1)
	if s := ctx.Seq(); s != nil {
		if st := s.Write(Line{Seq: ctx.SeqNum(), Tag: 0xE233}); st != 0 {
			Out.AtomicAdd(1, 1)
		}
	}
}

func main() {}
