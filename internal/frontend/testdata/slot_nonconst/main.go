package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var S = bpf.ProgArray{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

var n = uint32(1)

var _ = bpf.TailSlot(&S, n, next)

func next(ctx *bpf.XDPContext) bpf.XDPAction { return bpf.XDPPass }

func main() {}
