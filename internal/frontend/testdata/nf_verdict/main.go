package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// netfilter returns NFAction — XDPAction is the wrong type.
func onNF(ctx *bpf.NetfilterContext) bpf.NFAction {
	return bpf.XDPPass
}

func main() {}
