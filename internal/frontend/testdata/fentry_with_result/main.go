package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var C = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:fentry do_sys_poll
func f(ctx *bpf.FentryContext) bpf.XDPAction {
	return bpf.XDPPass
}

func main() {}
