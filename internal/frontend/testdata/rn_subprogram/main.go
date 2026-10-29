package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A subprogram name starting with `__ebpf_` — reserved by the compiler (bpf-mlir's outlined __ebpf_present_<function>_<n>): GB013.
var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

func __ebpf_present_Prog_0(x uint64) uint64 {
	return x + 1
}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, __ebpf_present_Prog_0(1))
	return bpf.XDPPass
}

func main() {}
