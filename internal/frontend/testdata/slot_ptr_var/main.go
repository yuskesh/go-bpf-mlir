package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var S = bpf.ProgArray{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

var p = &S

var _ = bpf.TailSlot(p, 0, next)

func next(ctx *bpf.XDPContext) bpf.XDPAction { return bpf.XDPPass }

func main() {}
