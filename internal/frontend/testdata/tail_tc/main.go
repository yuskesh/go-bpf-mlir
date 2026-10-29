package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var S = bpf.ProgArray{MaxEntries: 4}
var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

func f(ctx *bpf.TCIngressContext) bpf.TCAction {
	S.TailCall(ctx, 0)
	return bpf.TCPass
}

func main() {}
