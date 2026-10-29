package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

var Q = bpf.Queue[uint32]{MaxEntries: 4}

func f(ctx *bpf.XDPContext) bpf.XDPAction {
	Q.Pop()
	return bpf.XDPPass
}

func main() {}
