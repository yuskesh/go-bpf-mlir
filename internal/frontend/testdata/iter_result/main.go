package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Elems = bpf.Array[uint32, uint64]{MaxEntries: 6}

// An iter program has no result (done).
//
//gobpf:iter bpf_map_elem Elems
func f(ctx *bpf.IterContext) int32 {
	return 0
}

func main() {}
