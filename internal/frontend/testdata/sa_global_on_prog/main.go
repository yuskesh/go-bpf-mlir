package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

// //gobpf:global marks a subprogram — on a program function it is GB013 (never silently ignored).
//
//gobpf:global
func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, 1)
	return bpf.XDPPass
}

func main() {}
