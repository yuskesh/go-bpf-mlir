package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// A global with integer-only arguments — no argtag appears in the requirements (expected to pass the gate on 6.6.157 too).
var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

//gobpf:global
func sqG(x uint64) uint64 { return x * x }

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, sqG(5))
	return bpf.XDPPass
}

func main() {}
