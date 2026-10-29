package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Elems = bpf.Array[uint32, uint64]{MaxEntries: 6}

// The target must be bpf_map_elem — task is refused with a named error.
//
//gobpf:iter task Elems
func f(ctx *bpf.IterContext) {
}

func main() {}
