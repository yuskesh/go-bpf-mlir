package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

type Line struct {
	Seq uint64 `schema:"seq"`
}

var Elems = bpf.Array[uint32, uint64]{MaxEntries: 6}

// ctx.Seq() may be NULL — it cannot be used outside a nil check in an if init statement.
//
//gobpf:iter bpf_map_elem Elems
func f(ctx *bpf.IterContext) {
	_ = ctx.Seq().Write(Line{Seq: 1})
}

func main() {}
