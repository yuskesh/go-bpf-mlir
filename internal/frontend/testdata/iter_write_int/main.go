package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Elems = bpf.Array[uint32, uint64]{MaxEntries: 6}

// SeqFile.Write takes a record struct — integers cannot be written.
//
//gobpf:iter bpf_map_elem Elems
func f(ctx *bpf.IterContext) {
	if s := ctx.Seq(); s != nil {
		_ = s.Write(uint64(7))
	}
}

func main() {}
