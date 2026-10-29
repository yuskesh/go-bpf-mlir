package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A program name starting with `__ebpf_` — it is the BPF symbol name itself (reserved by the compiler): GB013.
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func __ebpf_count(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.AtomicAdd(0, 1)
	return bpf.XDPPass
}

func main() {}
