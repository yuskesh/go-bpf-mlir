package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// The directive has no target map for the iterator.
//
//gobpf:iter bpf_map_elem
func f(ctx *bpf.IterContext) {
}

func main() {}
