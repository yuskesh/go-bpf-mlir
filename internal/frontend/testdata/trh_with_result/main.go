package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Out = bpf.Array[uint32, uint64]{MaxEntries: 1}

//gobpf:raw_tp sys_enter
func f(ctx *bpf.RawTPContext) bpf.XDPAction {
	Out.Update(0, 1)
	return bpf.XDPPass
}

func main() {}
