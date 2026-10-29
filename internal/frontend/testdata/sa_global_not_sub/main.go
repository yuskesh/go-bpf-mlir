package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 4}

func Prog(ctx *bpf.XDPContext) bpf.XDPAction {
	Out.Update(0, 1)
	return bpf.XDPPass
}

// helper is not called from a program (a user-side function) — //gobpf:global is GB013.
//
//gobpf:global
func helper(x uint64) uint64 { return x + 1 }

func main() { _ = helper(1) }
