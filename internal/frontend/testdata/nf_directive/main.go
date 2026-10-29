package main

import "github.com/yuskesh/go-bpf-mlir/bpf"

// netfilter takes no directive (the type determines the kind; pf / hook / priority are arguments of gobpf.AttachNetfilter).
//
//gobpf:netfilter local_in
func onNF(ctx *bpf.NetfilterContext) bpf.NFAction {
	return bpf.NFAccept
}

func main() {}
